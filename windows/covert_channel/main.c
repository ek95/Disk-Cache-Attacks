/*-----------------------------------------------------------------------------
 * main.c
 *
 * A program demonstrating a covert channel based on
 * virtual memory and shared memory.
 *
 * Usage: ./covert [-t|-r|-s] [covert transmission file]
 *
 * Erik Kraft
 */

// target windows 8 and higher
#define _WIN32_WINNT 0x0602


/*-----------------------------------------------------------------------------
 * INCLUDES
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <windows.h>
#include <psapi.h>
#include <ntstatus.h>
#include <shlwapi.h>


/*-----------------------------------------------------------------------------
 * DEFINES
 */
// general defines
//#define _DEBUG_
#define TR_MEAS_FILE "tr.csv"
#define SENDER_READY_SEM_NAME "sender_ready_sem"
#define RECEIVER_READY_SEM_NAME "recv_ready_sem"
#define SEND_NOW_SEM_NAME "send_now_sem"
#define TST_MSG_SHM_NAME "tst_msg_shm"
#define RCVD_MSG_SHM_NAME "rcvd_msg_shm"
#define CMD_LINE_TST_SENDER "ev_chk -t -s "
#define CMD_LINE_TST_RCV "ev_chk -t -r "
#define TEST_RUNS 250

// defines used for parsing command line arguments
#define SEND 0
#define RECEIVE 1
#define TEST 2
const char *SWITCHES_STR[] = {"-s", "-r", "-t", NULL};
#define COVERT_FILENAME_STR 0

// defines for the covert channel function
#define MESSAGE_SIZE 8*1024
#define CONTROL_PAGES 4
#define COVERT_FILE_SIZE ((MESSAGE_SIZE * 8 + CONTROL_PAGES) * page_size)
const size_t ACK_PAGE_OFFSET[2] = {MESSAGE_SIZE * 8  + 2, MESSAGE_SIZE * 8  + 3};
const size_t READY_PAGE_OFFSET[2] = {MESSAGE_SIZE * 8, MESSAGE_SIZE * 8  + 1};

// defines used for formatting output
#define PENDING "[PENDING] "
#define INFO "[INFO] "
#define DEBUG "[DEBUG] "
#define OK "[OK] "
#define FAIL "[FAIL] "
#define USAGE "[USAGE] "


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
  HANDLE fh_;
  HANDLE mh_;
  void *addr_;
  size_t size_;
  size_t size_pages_;
  PSAPI_WORKING_SET_EX_INFORMATION *page_info_;
};


/*-----------------------------------------------------------------------------
 * FUNCTION PROTOTYPES
 */
void usageError(char *app_name);
int createRandomFile(char *filename, size_t covert_size);
void sendMsg(unsigned char *message, struct _MemRange_ *covert_mem);
void receiveMsg(unsigned char *message, struct _MemRange_ *covert_mem, int covert_file_locked_in_ws);
size_t getBitDiffCount(unsigned char *data, unsigned char *reference, size_t size);



/*-----------------------------------------------------------------------------
 * GLOBAL VARIABLES
 */
static int running = 1;
size_t page_size = 0;
LARGE_INTEGER pc_frequency = {0};
TCHAR module_path[MAX_PATH] = {0};

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
BOOL quitHandler(DWORD fdwCtrlType)
{
  running = 0;
  return TRUE;
}


/*-----------------------------------------------------------------------------
 * CODE
 */
int main(int argc, char *argv[])
{
  // general variables
  LARGE_INTEGER transmission_start, transmission_end;
  int return_value = 0;

  // variables used for processing command line arguments
  int mode = 0;
  char *arg_strings[3] = {NULL};
  size_t arg_i = 1, str_i = 0, sw = 0;

  // variables used for statistics
  FILE *tr_meas_file = NULL;
  size_t elapsed_time_us = 0;
  double tr_kb_sum = 0;

  // variables necessary for general exploit function
  SYSTEM_INFO sys_info;
  MEMORYSTATUSEX mem_stat;
  STARTUPINFO startup_info;
  PROCESS_INFORMATION process_info;
  struct _MemRange_ covert_mem = {0};
  size_t current_ws_min_size, current_ws_max_size;
  int covert_file_lockable_in_ws = 0;
  HANDLE h_sender_ready_sem, h_receiver_ready_sem, h_send_now_sem;
  HANDLE h_tst_msg_shm, h_rcvd_msg_shm;
  HANDLE h_rcv_proc, h_send_proc;
  char *message;
  unsigned char *tst_msg, *rcvd_msg;
  char cmd_line[MAX_PATH + sizeof(CMD_LINE_TST_SENDER)] = {0};
  size_t bit_error_count = 0;
  size_t bit_error_sum = 0;

  srand(time(NULL));


  GetModuleFileNameA(NULL, module_path, MAX_PATH);
  if(GetLastError() != ERROR_SUCCESS)
  {
    printf(FAIL "Error (%d) at GetModuleFileNameA...\n", GetLastError());
    goto main_error;
  }

  // process command line arguments
  for(; arg_i < argc; arg_i++)
  {
    for(sw = 0; SWITCHES_STR[sw] != NULL; sw++)
    {
      if (strcmp(argv[arg_i], SWITCHES_STR[sw]) == 0)
      {
        mode |= (1 << sw);
        break;
      }
    }

    // switches have to be before strings
    if(str_i != 0 && SWITCHES_STR[sw] != NULL)
    {
      usageError(argv[0]);
    }
    else if(SWITCHES_STR[sw] == NULL)
    {
      arg_strings[str_i] = argv[arg_i];
      str_i++;

      // too many argument strings
      if(str_i > 1)
      {
        usageError(argv[0]);
      }
    }
  }
  // too less argument strings
  if(str_i < 1)
  {
    usageError(argv[0]);
  }


  // register signal handler for quiting the program by STRG+C
  if(!SetConsoleCtrlHandler((PHANDLER_ROUTINE) quitHandler, TRUE))
  {
    printf(FAIL "Error (%lu) at SetConsoleCtrlHandler...\n", GetLastError());
    goto main_error;
  }

  // retrieve frequency of performance counter
  QueryPerformanceFrequency(&pc_frequency);

  // get system information
  GetSystemInfo(&sys_info);
  page_size = sys_info.dwPageSize;

  // get system memory information
  mem_stat.dwLength = sizeof(mem_stat);
  if(!GlobalMemoryStatusEx(&mem_stat))
  {
    printf(FAIL "Error (%lu) at GlobalMemoryStatusEx...\n", GetLastError());
    goto main_error;
  }
  printf(OK "Total usable ram: %Iu\n", mem_stat.ullTotalPhys);
  printf(INFO "Available physical ram: %Iu\n", mem_stat.ullAvailPhys);
  printf(INFO "Available paging file memory: %Iu\n", mem_stat.ullAvailPageFile);

  // get current working set size
  if(!GetProcessWorkingSetSize(GetCurrentProcess(), &current_ws_min_size, &current_ws_max_size))
  {
    printf(FAIL "Error (%lu) at GetProcessWorkingSetSize...\n", GetLastError());
    goto main_error;
  }
  current_ws_max_size = mem_stat.ullTotalPhys - 512 * page_size;

  if(!SetProcessWorkingSetSizeEx(GetCurrentProcess(), COVERT_FILE_SIZE + current_ws_min_size, current_ws_max_size,
                                 QUOTA_LIMITS_HARDWS_MIN_ENABLE))
  {
    printf(INFO "Error (%d) at SetProcessWorkingSetSize, therefore it may not be possible to keep the file for covert "
                "transmission completely in the ws, prepare for a higher error rate.\n", GetLastError());
  } else
  {
    covert_file_lockable_in_ws = 1;
    printf(INFO "Process working set size min: %Iu and max: %Iu.\n", COVERT_FILE_SIZE + current_ws_min_size,
           current_ws_max_size);
  }

  // create covert channel file if it doesn't exist
  return_value = createRandomFile(arg_strings[COVERT_FILENAME_STR], COVERT_FILE_SIZE);
  if(return_value != 0)
  {
    printf(FAIL "Error at creating covert file...\n");
    goto main_error;
  }

  // map covert channel file
  covert_mem.fh_ = CreateFileA(arg_strings[COVERT_FILENAME_STR], GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, NULL,
    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if(covert_mem.fh_ == INVALID_HANDLE_VALUE)
  {
    printf(FAIL "Couldn't open file %s...\n", arg_strings[COVERT_FILENAME_STR]);
    goto main_error;
  }
  covert_mem.size_ = COVERT_FILE_SIZE;
  covert_mem.size_pages_ = ((covert_mem.size_ + page_size - 1) / page_size);
  covert_mem.mh_ = CreateFileMappingA(covert_mem.fh_, NULL, PAGE_EXECUTE_READ, 0, 0, NULL);
  if(covert_mem.mh_ == NULL)
  {
    printf(FAIL "Error (%d) at CreateFileMappingA %s...\n", GetLastError(), arg_strings[COVERT_FILENAME_STR]);
    goto main_error;
  }
  covert_mem.addr_ = MapViewOfFile(covert_mem.mh_, FILE_MAP_READ | FILE_MAP_EXECUTE, 0, 0, 0);
  if(covert_mem.addr_ == NULL)
  {
    printf(FAIL "Error (%d) at MapViewOfFile %s...\n", GetLastError(), arg_strings[COVERT_FILENAME_STR]);
    goto main_error;
  }
  covert_mem.page_info_ = malloc(covert_mem.size_pages_ * sizeof(PSAPI_WORKING_SET_EX_INFORMATION));
  if(covert_mem.page_info_ == NULL)
  {
    printf(FAIL "Error (%s) at malloc...\n", strerror(errno));
    goto main_error;
  }
  for(size_t p = 0; p < covert_mem.size_pages_; p++)
  {
    covert_mem.page_info_[p].VirtualAddress = covert_mem.addr_ + p * page_size;
  }

  message = calloc(MESSAGE_SIZE, sizeof(char));
  if(message == NULL)
  {
    printf(FAIL "Error (%s) at malloc...\n", strerror(errno));
    goto main_error;
  }

  // sender
  if(mode & (1<<SEND))
  {
    // prepare sender for testing performance
    if(mode & (1<<TEST))
    {
      // open semaphores
      h_sender_ready_sem = OpenSemaphoreA(SYNCHRONIZE | SEMAPHORE_MODIFY_STATE, FALSE, SENDER_READY_SEM_NAME);
      h_send_now_sem = OpenSemaphoreA(SYNCHRONIZE | SEMAPHORE_MODIFY_STATE, FALSE, SEND_NOW_SEM_NAME);
      if (h_sender_ready_sem == NULL || h_send_now_sem == NULL)
      {
        printf(FAIL "Error at opening semaphore %s or %s.\n", SENDER_READY_SEM_NAME, SEND_NOW_SEM_NAME);
        goto main_error;
      }

      // open shm
      h_tst_msg_shm = OpenFileMapping(FILE_MAP_READ, FALSE, TST_MSG_SHM_NAME);
      if(h_tst_msg_shm == NULL)
      {
        printf(FAIL "Error (%d) at OpenFileMapping %s...\n", GetLastError(), TST_MSG_SHM_NAME);
        goto main_error;
      }

      // map shm
      tst_msg = MapViewOfFile(h_tst_msg_shm, FILE_MAP_READ, 0, 0, MESSAGE_SIZE);
      if(tst_msg == NULL)
      {
        printf(FAIL "Error (%d) at MapViewOfFile %s...\n", GetLastError(), TST_MSG_SHM_NAME);
        goto main_error;
      }
    }

    printf(INFO "Initialsing send mode...\n");
    // lock ACK pages into ws (only read)
    VirtualLock(covert_mem.addr_ + ACK_PAGE_OFFSET[0] * page_size, 2 * page_size);
    printf(OK"Ready...\n");

    if(mode & (1<<TEST))
    {
      ReleaseSemaphore(h_sender_ready_sem, 1, 0);
    }

    while(running)
    {
      if(mode & (1<<TEST))
      {
        WaitForSingleObject(h_send_now_sem, INFINITE);
        sendMsg(tst_msg, &covert_mem);
      }
      else
      {
        memset(message, 0, MESSAGE_SIZE);
        fgets(message, MESSAGE_SIZE, stdin);
        sendMsg(message, &covert_mem);
      }
    }
  }
  // receiver
  else if(mode & (1<<RECEIVE))
  {
    // prepare receiver for performance test mode
    if(mode & (1<<TEST))
    {
      // open semaphores
      h_receiver_ready_sem = OpenSemaphoreA(SYNCHRONIZE | SEMAPHORE_MODIFY_STATE, FALSE, RECEIVER_READY_SEM_NAME);
      if (h_receiver_ready_sem == NULL)
      {
        printf(FAIL "Error (%d) at opening semaphore %s.\n", GetLastError(), RECEIVER_READY_SEM_NAME);
        goto main_cleanup;
      }

      // open shm
      h_rcvd_msg_shm = OpenFileMapping(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, RCVD_MSG_SHM_NAME);
      if(h_rcvd_msg_shm == NULL)
      {
        printf(FAIL "Error (%d) at OpenFileMapping %s...\n", GetLastError(), RCVD_MSG_SHM_NAME);
        goto main_error;
      }

      // map shm
      rcvd_msg = MapViewOfFile(h_rcvd_msg_shm, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, MESSAGE_SIZE);
      if(rcvd_msg == NULL)
      {
        printf(FAIL "Error (%d) at MapViewOfFile %s...\n", GetLastError(), RCVD_MSG_SHM_NAME);
        goto main_error;
      }
    }

    printf(INFO "Initialsing receive mode...\n");
    // lock READY pages into ws (only read)
    VirtualLock(covert_mem.addr_ + READY_PAGE_OFFSET[0] * page_size, 2 * page_size);
    // access ack
    VirtualLock(covert_mem.addr_ + ACK_PAGE_OFFSET[0] * page_size, page_size);
    // lock covert file if possible
    if(covert_file_lockable_in_ws)
    {
      if(!VirtualLock(covert_mem.addr_, covert_mem.size_ - CONTROL_PAGES * page_size))
      {
        printf(FAIL "Error (%d) at VirtualLock, switch to fallback receive mode...\n", GetLastError());
        covert_file_lockable_in_ws = 0;
      }
    }
    printf(OK"Ready...\n");

    if(mode & (1<<TEST))
    {
      ReleaseSemaphore(h_receiver_ready_sem, 1, 0);
    }

    while(running)
    {
      memset(message, 0, MESSAGE_SIZE);

      if(mode & (1<<TEST))
      {
        receiveMsg(rcvd_msg, &covert_mem, covert_file_lockable_in_ws);
        ReleaseSemaphore(h_receiver_ready_sem, 1, 0);
      }
      else
      {
        receiveMsg(message, &covert_mem, covert_file_lockable_in_ws);
        printf("Message: %s\n", message);
      }
    }
  }
  // test mode
  else if(mode & (1<<TEST))
    {
      printf(INFO "Starting performance test mode...\n");

      // create performance test file
      tr_meas_file = fopen(TR_MEAS_FILE, "w");
      if(tr_meas_file == NULL)
      {
        printf(FAIL "Error (%s) at fopen %s...\n", strerror(errno), TR_MEAS_FILE);
        goto main_error;
      }
      fprintf(tr_meas_file, "Message size (byte); %Iu\n\n", MESSAGE_SIZE);
      fprintf(tr_meas_file, "Run; Duration (us); Bit error count\n");

      // create semaphores
      h_sender_ready_sem = CreateSemaphoreA(NULL, 0, LONG_MAX, SENDER_READY_SEM_NAME);
      h_receiver_ready_sem = CreateSemaphoreA(NULL, 0, LONG_MAX, RECEIVER_READY_SEM_NAME);
      h_send_now_sem = CreateSemaphoreA(NULL, 0, LONG_MAX, SEND_NOW_SEM_NAME);
      if(h_sender_ready_sem == NULL && h_receiver_ready_sem == NULL && h_send_now_sem == NULL)
      {
        DEBUG_PRINT((DEBUG "Error at creation of semaphore...\n"));
        goto main_error;
      }

      // create shared memory
      h_tst_msg_shm = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, MESSAGE_SIZE,
                                         TST_MSG_SHM_NAME);
      h_rcvd_msg_shm = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, MESSAGE_SIZE,
                                          RCVD_MSG_SHM_NAME);
      if(h_tst_msg_shm == NULL || h_rcvd_msg_shm == NULL)
      {
        printf(FAIL "Error at CreateFileMappingA %s or %s..\n", TST_MSG_SHM_NAME, RCVD_MSG_SHM_NAME);
        goto main_error;
      }

      // map shared memory
      tst_msg = MapViewOfFile(h_tst_msg_shm, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, MESSAGE_SIZE);
      rcvd_msg = MapViewOfFile(h_rcvd_msg_shm, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, MESSAGE_SIZE);
      if(tst_msg == NULL || rcvd_msg == NULL)
      {
        printf(FAIL "Error at MapViewOfFile %s or %s...\n", TST_MSG_SHM_NAME, RCVD_MSG_SHM_NAME);
        goto main_error;
      }

      // preparing test data
      if(BCryptGenRandom(NULL, tst_msg, MESSAGE_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS)
      {
        printf(FAIL "Error (%d) at BCryptGenRandom...\n", GetLastError());
        goto main_cleanup;
      }

      // start sender and receiver process
      printf(INFO "Starting sender process...\n");
      ZeroMemory(&startup_info, sizeof(STARTUPINFO));
      startup_info.cb = sizeof(PROCESS_INFORMATION);
      ZeroMemory(&process_info, sizeof(process_info));
      strcpy(cmd_line, CMD_LINE_TST_SENDER);
      strncat(cmd_line, arg_strings[COVERT_FILENAME_STR], MAX_PATH - strlen(CMD_LINE_TST_SENDER));
      if(!CreateProcessA(module_path, cmd_line, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                     NULL, NULL, &startup_info, &process_info))
      {
        printf(FAIL "Error (%d) at CreateProcessA...\n", GetLastError());
        goto main_error;
      }
      h_send_proc = process_info.hProcess;

      WaitForSingleObject(h_sender_ready_sem, INFINITE);

      printf(INFO"Starting receiver process...\n");
      ZeroMemory(&startup_info, sizeof(STARTUPINFO));
      startup_info.cb = sizeof(PROCESS_INFORMATION);
      ZeroMemory(&process_info, sizeof(process_info));
      strcpy(cmd_line, CMD_LINE_TST_RCV);
      strncat(cmd_line, arg_strings[COVERT_FILENAME_STR], MAX_PATH - strlen(CMD_LINE_TST_RCV));
      if(!CreateProcessA(module_path, cmd_line, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                     NULL, NULL, &startup_info, &process_info))
      {
        printf(FAIL "Error (%d) at CreateProcessA...\n", GetLastError());
        goto main_error;
      }
      h_rcv_proc = process_info.hProcess;

      WaitForSingleObject(h_receiver_ready_sem, INFINITE);

      size_t run = 0;
      for(; run < TEST_RUNS && running; run++)
      {
        QueryPerformanceCounter(&transmission_start);
        ReleaseSemaphore(h_send_now_sem, 1, 0);
        WaitForSingleObject(h_receiver_ready_sem, INFINITE);
        QueryPerformanceCounter(&transmission_end);

        elapsed_time_us = (transmission_end.QuadPart - transmission_start.QuadPart) * 1000000;
        elapsed_time_us /= pc_frequency.QuadPart;
        tr_kb_sum += ((double) MESSAGE_SIZE / elapsed_time_us) * 1000;

        printf(INFO "Run %Iu, duration: %Iuus...\n", run, elapsed_time_us);

        bit_error_count = getBitDiffCount(tst_msg, rcvd_msg, MESSAGE_SIZE);
        if(bit_error_count != 0)
        {
          printf(INFO "Warning exchanged messages differ at %Iubits...\n", bit_error_count);
          bit_error_sum += bit_error_count;
        }

        fprintf(tr_meas_file, "%Iu; %Iu; %Iu\n", run, elapsed_time_us, bit_error_count);
      }

      printf("\n" INFO "Average transmission speed %f kbytes/s of %Iu transmissions.\n",
             tr_kb_sum / run, run);
      printf(INFO "Bit error rate: %f%%\n", (double) bit_error_sum / (MESSAGE_SIZE * run * 8));
    }

  goto main_cleanup;

  main_error:
  return_value = -1;

  main_cleanup:

  CloseHandle(covert_mem.fh_);
  CloseHandle(covert_mem.mh_);
  free(message);
  free(covert_mem.page_info_);

  if(mode & (1<<TEST))
  {
    TerminateProcess(h_send_proc, 0);
    TerminateProcess(h_rcv_proc, 0);
    UnmapViewOfFile(tst_msg);
    UnmapViewOfFile(rcvd_msg);
    CloseHandle(h_tst_msg_shm);
    CloseHandle(h_rcvd_msg_shm);
    CloseHandle(h_sender_ready_sem);
    CloseHandle(h_receiver_ready_sem);
    CloseHandle(h_send_now_sem);
    fclose(tr_meas_file);
  }

  return return_value;
}


/*-----------------------------------------------------------------------------
 * FUNCTION DEFINITIONS
 */
int createRandomFile(char *filename, size_t covert_size)
{
  LARGE_INTEGER file_size;
  HANDLE random_file = NULL;
  char *buff = malloc(page_size);
  if(buff == NULL)
  {
    printf(FAIL "Error (%s) at malloc...\n", strerror(errno));
    return -1;
  }

  // file does already exist
  if(PathFileExistsA(filename))
  {
    random_file = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(random_file == INVALID_HANDLE_VALUE)
    {
      printf(FAIL "Error (%d) at CreateFileA for covert file...\n", GetLastError());
      return -1;
    }

    if(!GetFileSizeEx(random_file, &file_size))
    {
      printf(FAIL "Error (%d) at GetFileSizeEx for eviction file...\n", GetLastError());
      CloseHandle(random_file);
      return -1;
    }

    CloseHandle(random_file);

    if(file_size.QuadPart >= covert_size)
    {
      printf(OK "File %s already exists...\n", filename);
      return 0;
    }
  }

  // create new file
  printf(PENDING "Creating %Iu MB random file. This might take a while...\n", covert_size / 1024 / 1024);
  random_file = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if(random_file == INVALID_HANDLE_VALUE)
  {
    printf(FAIL "Error (%d) at CreateFileA for eviction file...\n", GetLastError());
    return -1;
  }

  for(size_t p = 0; p < covert_size; p += page_size)
  {
    if(BCryptGenRandom(NULL, (BYTE *) buff, page_size, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS)
    {
      printf(FAIL "Error (%d) at BCryptGenRandom...\n", GetLastError());
      CloseHandle(random_file);
      return -1;
    }

    if(!WriteFile(random_file, buff, page_size, NULL, NULL))
    {
      printf(FAIL "Error (%d) at WriteFile...\n", GetLastError());
      CloseHandle(random_file);
      return -1;
    }
  }

  CloseHandle(random_file);
  return 0;
}

void sendMsg(unsigned char *message, struct _MemRange_ *covert_mem)
{
  PSAPI_WORKING_SET_EX_INFORMATION page_info;
  volatile size_t access = 0;
  static int even = 0;
  char mask = 1;

  // wait for ack
  DEBUG_PRINT((DEBUG "Sender: Wait for ack %d.\n", even + 1));
  page_info.VirtualAddress = covert_mem->addr_ + ACK_PAGE_OFFSET[even] * page_size;
  do
  {
    //Sleep(1);
    QueryWorkingSetEx(GetCurrentProcess(), &page_info, (DWORD) sizeof(PSAPI_WORKING_SET_EX_INFORMATION));
  } while(page_info.VirtualAttributes.ShareCount < 2 && running);
  DEBUG_PRINT((DEBUG "Sender: Got ack.\n"));

  // throw covert file pages out of ws
  VirtualUnlock(covert_mem->addr_, covert_mem->size_ - CONTROL_PAGES * page_size);

  // access pages
  for(size_t p = 0, b = 0; p < (covert_mem->size_pages_ - CONTROL_PAGES); p++)
  {
    if(message[b] & mask)
    {
      access += *((size_t *) (covert_mem->addr_ + p * page_size));
    }

    mask = mask << 1;
    if(!mask)
    {
      mask = 1;
      b++;
    }
  }

  // unlock old ready
  VirtualUnlock(covert_mem->addr_ + READY_PAGE_OFFSET[even ^ 1] * page_size, page_size);
  VirtualUnlock(covert_mem->addr_ + READY_PAGE_OFFSET[even ^ 1] * page_size, page_size);

  // send new ready
  VirtualLock(covert_mem->addr_ + READY_PAGE_OFFSET[even] * page_size, page_size);

  DEBUG_PRINT((DEBUG "Sender: Send message + ready %d.\n", even + 1));

  even ^= 1;
}


void receiveMsg(unsigned char *message, struct _MemRange_ *covert_mem, int covert_file_locked_in_ws)
{
  PSAPI_WORKING_SET_EX_INFORMATION page_info;
  static int even = 0;
  char mask = 1;
  char byte = 0;

  // wait for ready
  DEBUG_PRINT((DEBUG
                "Receiver: Wait for ready %d.\n", even + 1));
  page_info.VirtualAddress = covert_mem->addr_ + READY_PAGE_OFFSET[even] * page_size;
  do
  {
    //Sleep(1);
    QueryWorkingSetEx(GetCurrentProcess(), &page_info, (DWORD) sizeof(PSAPI_WORKING_SET_EX_INFORMATION));
  } while(page_info.VirtualAttributes.ShareCount < 2 && running);

  DEBUG_PRINT((DEBUG
                "Receiver: Got ready.\n"));

  if(covert_file_locked_in_ws)
  {
    // receive ws information
    QueryWorkingSetEx(GetCurrentProcess(), covert_mem->page_info_,
                      (covert_mem->size_pages_ - CONTROL_PAGES) * sizeof(PSAPI_WORKING_SET_EX_INFORMATION));
  }
  else
  {
    // access pages (load into ws)
      for(size_t p = 0; p < (covert_mem->size_pages_ - CONTROL_PAGES); p++)
      {
        VirtualLock(covert_mem->addr_ + p * page_size, page_size);
        QueryWorkingSetEx(GetCurrentProcess(), &covert_mem->page_info_[p], sizeof(PSAPI_WORKING_SET_EX_INFORMATION));
        VirtualUnlock(covert_mem->addr_ + p * page_size, page_size);
        VirtualUnlock(covert_mem->addr_ + p * page_size, page_size);
      }
  }

  // get message
  for(size_t p = 0, b = 0; p < (covert_mem->size_pages_ - CONTROL_PAGES); p++)
  {
    if(covert_mem->page_info_[p].VirtualAttributes.Valid && covert_mem->page_info_[p].VirtualAttributes.ShareCount > 1)
    {
      byte |= mask;
    }

    mask = mask << 1;
    if(!mask)
    {
      message[b] = byte;

      b++;
      byte = 0;
      mask = 1;
    }
  }

  // unlock old ack
  VirtualUnlock(covert_mem->addr_ + ACK_PAGE_OFFSET[even] * page_size, page_size);
  VirtualUnlock(covert_mem->addr_ + ACK_PAGE_OFFSET[even] * page_size, page_size);

  even ^= 1;

  // send new ack
  VirtualLock(covert_mem->addr_ + ACK_PAGE_OFFSET[even] * page_size, page_size);
  DEBUG_PRINT((DEBUG "Receiver: Send ack %d.\n", even + 1));
}

size_t getBitDiffCount(unsigned char *data, unsigned char *reference, size_t size)
{
  size_t diff_count = 0;

  for(size_t byte = 0; byte < size; byte++)
  {
    diff_count += BITS_SET_BYTE[data[byte] ^ reference[byte]];
  }

  return diff_count;
}

void usageError(char *app_name)
{
  printf(USAGE "%s [-t|-r|-s] [covert transmission file]\n", app_name);
  exit(-1);
}
