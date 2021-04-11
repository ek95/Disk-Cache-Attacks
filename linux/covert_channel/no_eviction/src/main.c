/*-----------------------------------------------------------------------------
 * main.c
 *
 * A program demonstrating a covert channel using a side channel based on
 * virtual memory and shared memory. To run this demo program you should have
 * swapping disabled.
 *
 * Usage: ./covert [-s|-r|-t] [message + ack file] [ready file]
 *
 * Erik Kraft
 */

// needed to support additional features
#define _GNU_SOURCE 
#define _DEFAULT_SOURCE

/*-----------------------------------------------------------------------------
 * INCLUDES
 */
#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <zconf.h>
#include <memory.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <sys/mman.h>
#include <signal.h>
#include <semaphore.h>
#include <stdint.h>

/*-----------------------------------------------------------------------------
 * DEFINES
 */
// general defines
//#define _DEBUG_
// file names and paths
#define RANDOM_SRC "/dev/urandom"
#define NULL_PATH "/dev/null"
#define TR_MEAS_FILE "tr.csv"
#define TEST_RUNS 250

// defines used for parsing command line arguments
#define SEND 0
#define RECEIVE 1
#define TEST 2
const char *SWITCHES_STR[] = {"-s", "-r", "-t", NULL};
#define MESSAGE_ACK_FILENAME_STR 0
#define READY_FILENAME_STR 1

// defines for configurating the covert channel
#define MESSAGE_SIZE (8*1024)
#define MESSAGE_ACK_FILE_SIZE ((MESSAGE_SIZE * 8 + 1) * PAGE_SIZE)
#define READY_FILE_SIZE (2 * PAGE_SIZE)
#define ACK_PAGE_OFFSET (MESSAGE_SIZE * 8)
const size_t READY_PAGE_OFFSET[2] = {0, 1};

// defines used for formatting output
#define PENDING "\x1b[34;1m[PENDING]\x1b[0m "
#define INFO "\x1b[34;1m[INFO]\x1b[0m "
#define DEBUG "\x1b[35;1m[DEBUG]\x1b[0m "
#define OK "\x1b[32;1m[OK]\x1b[0m "
#define FAIL "\x1b[31;1m[FAIL]\x1b[0m "
#define USAGE "\x1b[31;1m[USAGE]\x1b[0m "
#define WARNING "\x1b[33;1m[WARNING]\x1b[0m "


/*-----------------------------------------------------------------------------
 * MACROS
 */
#ifdef _DEBUG_
# define DEBUG_PRINT(x) printf x
#else
# define DEBUG_PRINT(x) do {} while (0)
#endif


/*-----------------------------------------------------------------------------
 * TYPE DEFINITIONS
 */
struct _MemRange_
{
  char *filename_;
  int fd_;
  size_t size_;
  size_t size_pages_;
  void *addr_;
  unsigned char *page_status_;
};

struct _CovertTrMemRanges_
{
  struct _MemRange_ message_ack_mem_;
  struct _MemRange_ ready_mem_;
};


/*-----------------------------------------------------------------------------
 * FUNCTION PROTOTYPES
 */
int createRandomFile(char *filename, size_t file_size);
void sendMsg(char *message, struct _CovertTrMemRanges_ *covert_tr_mem_ranges);
void receiveMsg(char *message, struct _CovertTrMemRanges_ *covert_tr_mem_ranges);
size_t getMappingCount(unsigned char *status, size_t size_in_pages);
size_t getBitDiffCount(unsigned char *data, unsigned char *reference, size_t size);
void usageError(char *app_name);


/*-----------------------------------------------------------------------------
 * GLOBAL VARIABLES
 */
static int running = 1;
static size_t PAGE_SIZE = 0;

#define SC_2B(n) n, n + 1, n + 1, n + 2
#define SC_4B(n) SC_2B(n), SC_2B(n + 1), SC_2B(n + 1), SC_2B(n + 2)
#define SC_6B(n) SC_4B(n), SC_4B(n + 1), SC_4B(n + 1), SC_4B(n + 2)
static const unsigned char BITS_SET_BYTE[256] =
    {
        SC_6B(0), SC_6B(1), SC_6B(1), SC_6B(2)
    };


/*-----------------------------------------------------------------------------
 * SIGNAL HANDLERS
 */
void quitHandler(int signal)
{
  running = 0;
}


/*-----------------------------------------------------------------------------
 * CODE
 */
int main(int argc, char *argv[])
{
  // general variables
  struct sysinfo system_info;
  struct sigaction quit_act = {0};
  struct timespec request_start, request_end;
  int return_value = 0;

  // variables used for processing command line arguments
  int mode = 0;

  // variables used for statistics
  FILE *tr_meas_file = NULL;
  size_t elapsed_time_ns = 0;
  double tr_kb_sum = 0;
  size_t bit_error_count = 0, bit_error_sum = 0;

  // variables necessary for general covert channel function
  struct _CovertTrMemRanges_ covert_tr_mem_ranges = {0};
  pid_t sender_pid = 0, receiver_pid = 0;
  sem_t *sender_ready = NULL, *receiver_ready = NULL, *send_now = NULL;
  char *message;
  char *tst_msg = NULL, *rcvd_msg = NULL;
  int random_fd = 0, null_fd = 0;
  volatile uint8_t access = 0;

  // variables for command line parsing
  size_t arg_i = 1, str_i = 0, sw = 0;
  char *arg_strings[2] = {NULL};


  // process command line arguments
  for (; arg_i < argc; arg_i++)
  {
    for (sw = 0; SWITCHES_STR[sw] != NULL; sw++)
    {
      if (strcmp(argv[arg_i], SWITCHES_STR[sw]) == 0)
      {
        mode = sw;
        break;
      }
    }

    // switches have to be before strings
    if (str_i != 0 && SWITCHES_STR[sw] != NULL)
    {
      usageError(argv[0]);
    } else if (SWITCHES_STR[sw] == NULL)
    {
      arg_strings[str_i] = argv[arg_i];
      str_i++;

      // too many argument strings
      if (str_i > 2)
      {
        usageError(argv[0]);
      }
    }
  }
  // too less argument strings
  if (str_i < 2)
  {
    usageError(argv[0]);
  }

  // register signal handler for quiting the program by SRTG+C
  quit_act.sa_handler = quitHandler;
  return_value = sigaction(SIGINT, &quit_act, NULL);
  return_value += sigaction(SIGQUIT, &quit_act, NULL);
  if (return_value != 0)
  {
    printf(FAIL "Error at registering signal handlers...\n");
  }

  // get system page size
  PAGE_SIZE = sysconf(_SC_PAGESIZE);
  if (PAGE_SIZE == -1)
  {
    printf(FAIL "Error (%s) at syscconf...\n", strerror(errno));
    goto error;
  }
  printf(INFO "System page size: %zu.\n", PAGE_SIZE);

  // get system information
  return_value = sysinfo(&system_info);
  if (return_value != 0)
  {
    printf(FAIL "Error (%s) at sysinfo...\n", strerror(errno));
    goto error;
  }
  printf(OK "Total usable ram %zu\n", system_info.totalram);

  // allocate memory for message
  message = malloc(MESSAGE_SIZE * sizeof(char));
  if (message == NULL)
  {
    printf(FAIL "Error (%s) at malloc...\n", strerror(errno));
    goto error;
  }

  // create message + ack file if it doesn't exist
  return_value = createRandomFile(arg_strings[MESSAGE_ACK_FILENAME_STR], MESSAGE_ACK_FILE_SIZE);
  if (return_value != 0)
  {
    printf(FAIL "Error at creating message + ack file...\n");
    goto error;
  }

  // create ready file if it doesn't exist
  return_value = createRandomFile(arg_strings[READY_FILENAME_STR], READY_FILE_SIZE);
  if (return_value != 0)
  {
    printf(FAIL "Error at creating ready file...\n");
    goto error;
  }

  // performance testing mode
  if (mode == TEST)
  {
    printf(INFO "Starting performance test mode...\n");

    // open random number generator and null device
    random_fd = open(RANDOM_SRC, O_RDONLY);
    null_fd = open(NULL_PATH, O_WRONLY);
    if (random_fd < 0 || null_fd < 0)
    {
      printf(FAIL "Error at opening /dev/urandom or /dev/null...\n");
      goto error;
    }

    // create shared semaphores
    sender_ready = mmap(NULL, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    receiver_ready = mmap(NULL, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    send_now = mmap(NULL, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (sender_ready == MAP_FAILED || receiver_ready == MAP_FAILED || send_now == MAP_FAILED)
    {
      printf(FAIL "Error at mmap for memory for semaphores...\n");
      goto error;
    }

    // initialize semaphores
    sem_init(sender_ready, 1, 0);
    sem_init(receiver_ready, 1, 0);
    sem_init(send_now, 1, 0);
    tst_msg = mmap(NULL, MESSAGE_SIZE * sizeof(char), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    rcvd_msg = mmap(NULL, MESSAGE_SIZE * sizeof(char), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (tst_msg == MAP_FAILED || rcvd_msg == MAP_FAILED)
    {
      printf(FAIL "Error at mmap tst_msg or rcvd_msg...\n");
      goto error;
    }

    // preparing test data
    /*if(read(random_fd, tst_msg, MESSAGE_SIZE) != MESSAGE_SIZE) 
    {
	    printf(FAIL "Error (%s) at read...\n", strerror(errno));
      goto error;
    }*/

    // start sender process
    printf(INFO "Starting sender process...\n");
    sender_pid = fork();
    if (sender_pid < 0)
    {
      printf(FAIL "Error (%s) at fork...\n", strerror(errno));
      goto error;
    }
      // child
    else if (sender_pid == 0)
    {
      dup2(null_fd, STDOUT_FILENO);
      mode = SEND;
      goto send_recv_mode;
    }

    sem_wait(sender_ready);

    // start receiver process
    printf(INFO "Starting receiver process...\n");
    receiver_pid = fork();
    if (receiver_pid < 0)
    {
      printf(FAIL "Error (%s) at fork...\n", strerror(errno));
      goto error;
    }
      // child
    else if (receiver_pid == 0)
    {
      dup2(null_fd, STDOUT_FILENO);
      mode = RECEIVE;
      goto send_recv_mode;
    }

    sem_wait(receiver_ready);

    // create performance test file
    // do not move before fork() without flushing buffer as each child will then
    // flush its buffer!
    tr_meas_file = fopen(TR_MEAS_FILE, "w");
    if (tr_meas_file == NULL)
    {
      printf(FAIL "Error (%s) at fopen %s...\n", strerror(errno), TR_MEAS_FILE);
      goto error;
    }
    fprintf(tr_meas_file, "Message size (byte); %u\n\n", MESSAGE_SIZE);
    fprintf(tr_meas_file, "Run; Duration (ns); Bit error count\n");

    printf(INFO "Ready, beginning with test process...\n");

    size_t run = 0;
    for (; run < TEST_RUNS && running; run++)
    {
      // preparing test data
      if(read(random_fd, tst_msg, MESSAGE_SIZE) != MESSAGE_SIZE) 
      {
        printf(WARNING "Partial read from %s.\n", RANDOM_SRC);
      }
            

      clock_gettime(CLOCK_REALTIME, &request_start);
      sem_post(send_now);
      sem_wait(receiver_ready);
      clock_gettime(CLOCK_REALTIME, &request_end);

      elapsed_time_ns = (request_end.tv_sec - request_start.tv_sec) * 1000000000 +
                        (request_end.tv_nsec - request_start.tv_nsec);

      tr_kb_sum += ((double) MESSAGE_SIZE / elapsed_time_ns) * 1000000;

      printf(INFO "Run %zu, duration: %zuns...\n", run, elapsed_time_ns);

      bit_error_count = getBitDiffCount((unsigned char *) tst_msg, (unsigned char *) rcvd_msg, MESSAGE_SIZE);
      if (bit_error_count != 0)
      {
        printf(INFO "Warning exchanged messages differ at %zubits...\n", bit_error_count);
        bit_error_sum += bit_error_count;
      }

      fprintf(tr_meas_file, "%zu; %zu; %zu\n", run, elapsed_time_ns, bit_error_count);
    }

    printf("\n" INFO "Average transmission speed %f kbytes/s of %zu transmissions.\n",
           tr_kb_sum / run, run);
    printf(INFO "Bit error rate: %f%%\n", (double) bit_error_sum / (MESSAGE_SIZE * run * 8));

    goto cleanup;
  }

  send_recv_mode:

  printf(INFO "For manual mode please ensure that the sender is started before the receiver...\n");

  // open and map message + ack file
  covert_tr_mem_ranges.message_ack_mem_.fd_ = open(arg_strings[MESSAGE_ACK_FILENAME_STR], O_RDONLY);
  if (covert_tr_mem_ranges.message_ack_mem_.fd_ < 0)
  {
    printf(FAIL "Error (%s) at open %s...\n", strerror(errno), arg_strings[MESSAGE_ACK_FILENAME_STR]);
    goto error;
  }
  covert_tr_mem_ranges.message_ack_mem_.size_ = MESSAGE_ACK_FILE_SIZE;
  covert_tr_mem_ranges.message_ack_mem_.size_pages_ = MESSAGE_ACK_FILE_SIZE / PAGE_SIZE;
  covert_tr_mem_ranges.message_ack_mem_.page_status_ = malloc(
      covert_tr_mem_ranges.message_ack_mem_.size_pages_ * sizeof(unsigned char));
  if (covert_tr_mem_ranges.message_ack_mem_.page_status_ == NULL)
  {
    printf(FAIL "Error (%s) at malloc...\n", strerror(errno));
    goto error;
  }
  covert_tr_mem_ranges.message_ack_mem_.addr_ = mmap(NULL, covert_tr_mem_ranges.message_ack_mem_.size_,
                                                     PROT_READ | PROT_EXEC, MAP_PRIVATE,
                                                     covert_tr_mem_ranges.message_ack_mem_.fd_, 0);
  if (covert_tr_mem_ranges.message_ack_mem_.addr_ == MAP_FAILED)
  {
    printf(FAIL "Error (%s) at mmap %s...\n", strerror(errno), arg_strings[MESSAGE_ACK_FILENAME_STR]);
    goto error;
  }
  covert_tr_mem_ranges.message_ack_mem_.filename_ = arg_strings[MESSAGE_ACK_FILENAME_STR];
  // evict loaded pages (possible readahead)
  posix_fadvise(covert_tr_mem_ranges.message_ack_mem_.fd_, 0, 0, POSIX_FADV_DONTNEED);
  madvise(covert_tr_mem_ranges.message_ack_mem_.addr_, covert_tr_mem_ranges.message_ack_mem_.size_, MADV_DONTNEED);
  // set access to random
  posix_fadvise(covert_tr_mem_ranges.message_ack_mem_.fd_, 0, 0, POSIX_FADV_RANDOM);
  madvise(covert_tr_mem_ranges.message_ack_mem_.addr_, covert_tr_mem_ranges.message_ack_mem_.size_, MADV_RANDOM);


  // open and map ready file
  covert_tr_mem_ranges.ready_mem_.fd_ = open(arg_strings[READY_FILENAME_STR], O_RDONLY);
  if (covert_tr_mem_ranges.ready_mem_.fd_ < 0)
  {
    printf(FAIL "Error (%s) at open %s...\n", strerror(errno), arg_strings[READY_FILENAME_STR]);
    goto error;
  }
  covert_tr_mem_ranges.ready_mem_.size_ = READY_FILE_SIZE;
  covert_tr_mem_ranges.ready_mem_.size_pages_ = READY_FILE_SIZE / PAGE_SIZE;
  covert_tr_mem_ranges.ready_mem_.page_status_ = malloc(covert_tr_mem_ranges.ready_mem_.size_pages_ * sizeof(char));
  if (covert_tr_mem_ranges.ready_mem_.page_status_ == NULL)
  {
    printf(FAIL "Error (%s) at malloc...\n", strerror(errno));
    goto error;
  }
  covert_tr_mem_ranges.ready_mem_.addr_ = mmap(NULL, covert_tr_mem_ranges.ready_mem_.size_,
                                               PROT_READ | PROT_EXEC, MAP_PRIVATE,
                                               covert_tr_mem_ranges.ready_mem_.fd_, 0);
  if (covert_tr_mem_ranges.ready_mem_.addr_ == MAP_FAILED)
  {
    printf(FAIL "Error (%s) at mmap %s...\n", strerror(errno), arg_strings[READY_FILENAME_STR]);
    goto error;
  }
  covert_tr_mem_ranges.ready_mem_.filename_ = arg_strings[READY_FILENAME_STR];
  // evict loaded pages (possible readahead)
  posix_fadvise(covert_tr_mem_ranges.ready_mem_.fd_, 0, 0, POSIX_FADV_DONTNEED);
  madvise(covert_tr_mem_ranges.ready_mem_.addr_, covert_tr_mem_ranges.ready_mem_.size_, MADV_DONTNEED);
  // set access to random
  posix_fadvise(covert_tr_mem_ranges.ready_mem_.fd_, 0, 0, POSIX_FADV_RANDOM);
  madvise(covert_tr_mem_ranges.ready_mem_.addr_, covert_tr_mem_ranges.ready_mem_.size_, MADV_RANDOM);

  // send mode
  if (mode == SEND)
  {
    printf(INFO "Initialising send mode...\n");

    if (sender_ready)
    {
      sem_post(sender_ready);
    }

    printf(OK "Ready...\n");

    while (running)
    {
      if (tst_msg)
      {
        sem_wait(send_now);
        sendMsg(tst_msg, &covert_tr_mem_ranges);
      } else
      {
        memset(message, 0, MESSAGE_SIZE);
        if(fgets(message, MESSAGE_SIZE, stdin) == NULL) 
        {
		  printf(FAIL "Error (%s) at fgets...\n", strerror(errno));
          goto error;
		}
        sendMsg(message, &covert_tr_mem_ranges);
      }
    }
  }
    // receive mode
  else if (mode == RECEIVE)
  {
    printf(INFO "Initialsing receive mode...\n");

    if (receiver_ready)
    {
      sem_post(receiver_ready);
    }
    // access initial ack
    access += *((uint8_t *) covert_tr_mem_ranges.message_ack_mem_.addr_ + ACK_PAGE_OFFSET * PAGE_SIZE);

    // unmap + close file (so that fadvise + madvise by other party are guaranteed to work)
    munmap(covert_tr_mem_ranges.message_ack_mem_.addr_, covert_tr_mem_ranges.message_ack_mem_.size_);
    covert_tr_mem_ranges.message_ack_mem_.addr_ = MAP_FAILED;
    close(covert_tr_mem_ranges.message_ack_mem_.fd_);
    covert_tr_mem_ranges.message_ack_mem_.fd_ = -1;

    printf(OK "Ready...\n");

    while (running)
    {
      memset(message, 0, MESSAGE_SIZE);

      if (rcvd_msg)
      {
        receiveMsg(rcvd_msg, &covert_tr_mem_ranges);
        sem_post(receiver_ready);
      } else
      {
        receiveMsg(message, &covert_tr_mem_ranges);
        printf("%s\n", message);
      }
    }
  }

  goto cleanup;

  error:
  return_value = -1;

  cleanup:

  free(covert_tr_mem_ranges.message_ack_mem_.page_status_);
  munmap(covert_tr_mem_ranges.message_ack_mem_.addr_, covert_tr_mem_ranges.message_ack_mem_.size_);
  close(covert_tr_mem_ranges.message_ack_mem_.fd_);

  free(covert_tr_mem_ranges.ready_mem_.page_status_);
  munmap(covert_tr_mem_ranges.ready_mem_.addr_, covert_tr_mem_ranges.ready_mem_.size_);
  close(covert_tr_mem_ranges.ready_mem_.fd_);


  if (mode == TEST)
  {
    kill(sender_pid, SIGQUIT);
    kill(receiver_pid, SIGQUIT);
    munmap(tst_msg, MESSAGE_SIZE);
    munmap(rcvd_msg, MESSAGE_SIZE);
    munmap(sender_ready, sizeof(sem_t));
    munmap(receiver_ready, sizeof(sem_t));
    munmap(send_now, sizeof(sem_t));
    close(random_fd);
    close(null_fd);
    fclose(tr_meas_file);
  }

  return return_value;
}


void sendMsg(char *message, struct _CovertTrMemRanges_ *covert_tr_mem_ranges)
{
  static int even = 0;
  volatile uint8_t access = 0;
  unsigned char page_status = 0;
  char mask = 1;


  DEBUG_PRINT((DEBUG "Sender: Wait for ack.\n"));
  // wait for ack
  do
  {
    mincore((uint8_t *) covert_tr_mem_ranges->message_ack_mem_.addr_ + ACK_PAGE_OFFSET * PAGE_SIZE, PAGE_SIZE, &page_status);
  } while (!(page_status & 1) && running);
  DEBUG_PRINT((DEBUG  "Sender: Got ack.\n"));

  // remove message + ack file pages
  do
  {
    // remove pages with fadvise + madvise
    posix_fadvise(covert_tr_mem_ranges->message_ack_mem_.fd_, 0, 0, POSIX_FADV_DONTNEED);
    madvise(covert_tr_mem_ranges->message_ack_mem_.addr_, covert_tr_mem_ranges->message_ack_mem_.size_, MADV_DONTNEED);
    // check if pages are really removed
    mincore(covert_tr_mem_ranges->message_ack_mem_.addr_, covert_tr_mem_ranges->message_ack_mem_.size_,
            covert_tr_mem_ranges->message_ack_mem_.page_status_);
  } while (getMappingCount(covert_tr_mem_ranges->message_ack_mem_.page_status_,
                           covert_tr_mem_ranges->message_ack_mem_.size_pages_) != 0);
  // set access to file to random
  posix_fadvise(covert_tr_mem_ranges->message_ack_mem_.fd_, 0, 0, POSIX_FADV_RANDOM);
  madvise(covert_tr_mem_ranges->message_ack_mem_.addr_, covert_tr_mem_ranges->message_ack_mem_.size_, MADV_RANDOM);


  // access pages
  for (size_t p = 0, b = 0; p < covert_tr_mem_ranges->message_ack_mem_.size_pages_ - 1; p++)
  {
    if (message[b] & mask)
    {
      access += *((uint8_t *) covert_tr_mem_ranges->message_ack_mem_.addr_ + p * PAGE_SIZE);
    }

    mask = mask << 1;
    if (!mask)
    {
      mask = 1;
      b++;
    }
  }

  // open and map ready file
  if (covert_tr_mem_ranges->ready_mem_.fd_ < 0 || covert_tr_mem_ranges->ready_mem_.addr_ == MAP_FAILED)
  {
    covert_tr_mem_ranges->ready_mem_.fd_ = open(covert_tr_mem_ranges->ready_mem_.filename_, O_RDONLY);
    covert_tr_mem_ranges->ready_mem_.addr_ = mmap(NULL, covert_tr_mem_ranges->ready_mem_.size_,
                                                  PROT_READ | PROT_EXEC, MAP_PRIVATE,
                                                  covert_tr_mem_ranges->ready_mem_.fd_, 0);
  }

  // send ready
  access += *((uint8_t *) covert_tr_mem_ranges->ready_mem_.addr_ + READY_PAGE_OFFSET[even] * PAGE_SIZE);
  even ^= 1;

  // unmap and close ready file (so that fadvise + madvise by other party are guaranteed to work)
  munmap(covert_tr_mem_ranges->ready_mem_.addr_, covert_tr_mem_ranges->ready_mem_.size_);
  covert_tr_mem_ranges->ready_mem_.addr_ = MAP_FAILED;
  close(covert_tr_mem_ranges->ready_mem_.fd_);
  covert_tr_mem_ranges->ready_mem_.fd_ = -1;

  DEBUG_PRINT((DEBUG "Sender: Send message + ready.\n"));
}


void receiveMsg(char *message, struct _CovertTrMemRanges_ *covert_tr_mem_ranges)
{
  static int even = 0;
  volatile uint8_t access = 0;
  unsigned char ready_status = 0;
  char mask = 1;
  char byte = 0;

  DEBUG_PRINT((DEBUG "Receiver: Wait for ready %d.\n", even + 1));
  do
  {
    mincore((uint8_t *) covert_tr_mem_ranges->ready_mem_.addr_ + READY_PAGE_OFFSET[even] * PAGE_SIZE, PAGE_SIZE, &ready_status);
  } while (!(ready_status & 1) && running);
  DEBUG_PRINT((DEBUG "Receiver: Got ready %d.\n", even + 1));

  // remove ready file pages
  do
  {
    // remove pages with fadvise + madvise
    posix_fadvise(covert_tr_mem_ranges->ready_mem_.fd_, 0, 0, POSIX_FADV_DONTNEED);
    madvise(covert_tr_mem_ranges->ready_mem_.addr_, covert_tr_mem_ranges->ready_mem_.size_, MADV_DONTNEED);
    // check if pages are really removed
    mincore(covert_tr_mem_ranges->ready_mem_.addr_, covert_tr_mem_ranges->ready_mem_.size_,
            covert_tr_mem_ranges->ready_mem_.page_status_);
  } while (getMappingCount(covert_tr_mem_ranges->ready_mem_.page_status_, covert_tr_mem_ranges->ready_mem_.size_pages_) != 0);
  // set access to file to random
  posix_fadvise(covert_tr_mem_ranges->ready_mem_.fd_, 0, 0, POSIX_FADV_RANDOM);
  madvise(covert_tr_mem_ranges->ready_mem_.addr_, covert_tr_mem_ranges->ready_mem_.size_, MADV_RANDOM);

  // open and map ready file
  if (covert_tr_mem_ranges->message_ack_mem_.fd_ < 0 || covert_tr_mem_ranges->message_ack_mem_.addr_ == MAP_FAILED)
  {
    covert_tr_mem_ranges->message_ack_mem_.fd_ = open(covert_tr_mem_ranges->message_ack_mem_.filename_, O_RDONLY);
    covert_tr_mem_ranges->message_ack_mem_.addr_ = mmap(NULL, covert_tr_mem_ranges->message_ack_mem_.size_,
                                                        PROT_READ | PROT_EXEC, MAP_PRIVATE,
                                                        covert_tr_mem_ranges->message_ack_mem_.fd_, 0);
  }

  // receive information
  mincore(covert_tr_mem_ranges->message_ack_mem_.addr_, covert_tr_mem_ranges->message_ack_mem_.size_ - PAGE_SIZE,
          covert_tr_mem_ranges->message_ack_mem_.page_status_);

  // get message
  for (size_t p = 0, b = 0; p < covert_tr_mem_ranges->message_ack_mem_.size_pages_ - 1; p++)
  {
    if (covert_tr_mem_ranges->message_ack_mem_.page_status_[p] & 1)
    {
      byte |= mask;
    }

    mask = mask << 1;
    if (!mask)
    {
      message[b] = byte;

      b++;
      byte = 0;
      mask = 1;
    }
  }


  even ^= 1;

  // send ack
  access += *((uint8_t *) covert_tr_mem_ranges->message_ack_mem_.addr_ + ACK_PAGE_OFFSET * PAGE_SIZE);

  // unmap and close message + ack file (so that fadvise + madvise by other party are guaranteed to work)
  munmap(covert_tr_mem_ranges->message_ack_mem_.addr_, covert_tr_mem_ranges->message_ack_mem_.size_);
  covert_tr_mem_ranges->message_ack_mem_.addr_ = MAP_FAILED;
  close(covert_tr_mem_ranges->message_ack_mem_.fd_);
  covert_tr_mem_ranges->message_ack_mem_.fd_ = -1;

  DEBUG_PRINT((DEBUG "Receiver: Send ack.\n"));
}


int createRandomFile(char *filename, size_t file_size)
{
  int fd;
  struct stat file_stat;
  struct statvfs filesys_stat;
  char cwd[PATH_MAX] = {0};

  fd = open(filename, O_CREAT | O_WRONLY | O_EXCL, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if (fd < 0)
  {
    if (errno != EEXIST)
    {
      return -1;
    }

    if (stat(filename, &file_stat) != 0)
    {
      printf(FAIL "Error (%s) at stat for %s...\n", strerror(errno), filename);
      return -1;
    }

    if (file_stat.st_size < file_size)
    {
      close(fd);
      fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
      if (fd < 0)
      {
        return -1;
      }
    } else
    {
      printf(OK "File %s already exists...\n", filename);
      return 0;
    }
  }

  // create new file
  printf(PENDING "Creating %zd MB random file. This might take a while...\n", file_size / 1024 / 1024);
  if (getcwd(cwd, sizeof(cwd)) == NULL)
  {
    printf(FAIL "Error (%s) at getcwd...\n", strerror(errno));
    return -1;
  }

  if (statvfs(cwd, &filesys_stat) != 0)
  {
    printf(FAIL "Error (%s) at getting free disk space...\n", strerror(errno));
    return -1;
  }

  // sanity checks
  size_t free_disk = filesys_stat.f_bsize * filesys_stat.f_bavail;
  if (free_disk < file_size)
  {
    printf(FAIL "Free disk space must be greater or equal memory size!\n");
    return -1;
  }

  // try fallocate first, if it fails fall back to the much slower file copy
  if (fallocate(fd, 0, 0, file_size) != 0)
  {
    // fallocate failed, fall back to creating eviction file from /dev/urandom
    close(fd);

    FILE *rnd_file = fopen("/dev/urandom", "rb");
    FILE *target_file = fopen(filename, "wb");
    size_t bs = 1 * 1024 * 1024;
    size_t rem = file_size;
    char *block = malloc(bs);

    if (rnd_file == NULL || target_file == NULL)
    {
      printf(FAIL "Error at opening /dev/random or %s...\n", filename);
      return -1;
    }

    if (block == NULL)
    {
      printf(FAIL "Error (%s) at malloc for block...\n", strerror(errno));
      return -1;
    }

    while (rem)
    {
      if (fread(block, bs, 1, rnd_file) != 1)
      {
        printf(FAIL "Error at reading from /dev/urandom...\n");
        fclose(rnd_file);
        fclose(target_file);
        free(block);
        return -1;
      }
      if (fwrite(block, bs, 1, target_file) != 1)
      {
        printf(FAIL "Error at writing to the random file...\n");
        fclose(rnd_file);
        fclose(target_file);
        free(block);
        return -1;
      }
      if (rem >= bs)
      {
        rem -= bs;
      } else
      {
        rem = 0;
      }
    }

    free(block);
    fclose(rnd_file);
    fclose(target_file);
  }

  close(fd);
  return 0;
}


size_t getMappingCount(unsigned char *status, size_t size_in_pages)
{
  size_t mapped = 0;

  for (size_t p = 0; p < size_in_pages; p++)
  {
    mapped += (status[p] & 1);
  }

  return mapped;
}


size_t getBitDiffCount(unsigned char *data, unsigned char *reference, size_t size)
{
  size_t diff_count = 0;

  for (size_t byte = 0; byte < size; byte++)
  {
    diff_count += BITS_SET_BYTE[data[byte] ^ reference[byte]];
  }

  return diff_count;
}


void usageError(char *app_name)
{
  printf(USAGE"%s [-s|-r|-t] [message_ack file] [ready file] \n", app_name);
  exit(-1);
}
