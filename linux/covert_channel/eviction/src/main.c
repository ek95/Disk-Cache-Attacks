/*-----------------------------------------------------------------------------
 * main.c
 *
 * A program demonstrating a covert channel using a side channel based on
 * virtual memory and shared memory. To run this demo program you should have
 * swapping disabled.
 *
 * May 2020 - Adapted new evict and check program with old strategy.
 *
 * Usage: ./covert_channel [covert channel file] [-s|-r|-t]
 *
 * Erik Kraft
 */

// needed to support additional features
#define _GNU_SOURCE
#define _DEFAULT_SOURCE

/*-----------------------------------------------------------------------------
 * INCLUDES
 */
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <memory.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <wait.h>
#include <zconf.h>
#include <assert.h>
#include "util/cmdline/cmdline.h"
#include "util/dynarray/dynarray.h"
#include "util/list/list.h"
#include "util/pageflags/pageflags.h"


/*-----------------------------------------------------------------------------
 * DEFINES
 */
// general defines
//#define _DEBUG_
#define FILE_COPY_BS (1*1024*1024)

// file names, paths and tags
#define EVICTION_FILENAME "eviction.ram"
char* OBJ_SEARCH_PATHS[] = { "/bin", "/dev/shm", "/etc", /*"/home",*/ "/lib", "/opt",
                             "/run", "/sbin", "/snap", "/tmp", "/usr", "/var", NULL
                           };
#define MEMINFO_PATH "/proc/meminfo"
#define RANDOM_SOURCE "/dev/urandom"
#define NULL_PATH "/dev/null"
#define TR_MEAS_FILE "tr.csv"
#define MEMINFO_AVAILABLE_MEM_TAG "MemAvailable:"


// defines used for parsing command line arguments
#define SWITCHES_COUNT 3
#define SEND_SWITCH 0
#define RECEIVE_SWITCH 1
#define TEST_SWITCH 2
const char *SWITCHES_STR[SWITCHES_COUNT] = {"-s", "-r", "-t"};
const size_t SWITCHES_ARG_COUNT[SWITCHES_COUNT] = { 0, 0, 0};
#define MANDATORY_ARGS 1
#define COVERT_FILENAME_ARG 0


// inits/limits for data structures
#define ARRAY_INIT_CAP 100
#define IN_LINE_MAX 255


// defines regarding the attacked system
#define DEF_PAGE_SIZE 4096
#define READAHEAD_PAGES 32


// defines for tuning the covert_channel
// no ws for covert channel - counter productive
#define DEF_USE_ATTACK_WS 1
#define DEF_USE_ATTACK_BS 1
#define DEF_MLOCK_SELF 1

#define DEF_WS_SEARCH_PATHS OBJ_SEARCH_PATHS
#define DEF_WS_PS_ADD_THRESHOLD READAHEAD_PAGES
#define DEF_WS_ACCESS_THREAD_COUNT 16
#define DEF_WS_ACCESS_THREADS_PER_CORE 4
#define DEF_WS_ACCESS_SLEEP_TIME_NS 4000000UL
#define DEF_WS_ACCESS_SLEEP_TIME_S 0UL
#define DEF_WS_EVALUATION 1
#define DEF_WS_EVICTION_IGNORE_EVALUATION 1
#define DEF_WS_EVALUATION_SLEEP_TIME_NS 0UL
#define DEF_WS_EVALUATION_SLEEP_TIME_S 1UL
// TODO not implemented
#define DEF_WS_PROFILE_UPDATE_ALL_X_EVALUATIONS 60

#define DEF_MINCORE_CHECK_ALL_X_BYTES (DEF_PAGE_SIZE * 6 * 1024UL)

#define DEF_BS_MEMINFO_FILE_PATH MEMINFO_PATH
#define DEF_BS_FILLUP_SIZE (16 * 1024 * 1024L)
#define DEF_BS_MIN_AVAILABLE_MEM (384 * 1024 * 1024L) // 384
#define DEF_BS_MAX_AVAILABLE_MEM (416 * 1024 * 1024L) // 416
#define DEF_BS_EVALUATION_SLEEP_TIME_NS 0UL
#define DEF_BS_EVALUATION_SLEEP_TIME_S 1UL

#define DEF_SAMPLE_WAIT_TIME_NS 10000UL

#define USE_NANOSLEEP

#define HYPERTHREADS_PER_CORE 2


// covert channel defines
#define MESSAGE_SIZE (8*1024)
#define CONTROL_PAGES 3
#define COVERT_FILE_SIZE ((MESSAGE_SIZE*8 + CONTROL_PAGES) * PAGE_SIZE)
#define ACK_PAGE_OFFSET (MESSAGE_SIZE*8)
const size_t READY_PAGE_OFFSET[2] = {MESSAGE_SIZE * 8 + 1, MESSAGE_SIZE * 8 + 2};
#define TEST_SWITCH_RUNS 100


// output TAGS with ANSI colors
#define PENDING "\x1b[34;1m[PENDING]\x1b[0m "
#define INFO "\x1b[34;1m[INFO]\x1b[0m "
#define EVENT "\x1b[33;1m[EVENT]\x1b[0m "
#define DEBUG "\x1b[35;1m[DEBUG]\x1b[0m "
#define OK "\x1b[32;1m[OK]\x1b[0m "
#define FAIL "\x1b[31;1m[FAIL]\x1b[0m "
#define USAGE "\x1b[31;1m[USAGE]\x1b[0m "
#define WARNING "\x1b[33;1m[WARNING]\x1b[0m "


// Thread TAGS
#define WS_MGR_TAG "[WS Manager] "
#define BS_MGR_TAG "[BS Manager] "
#define SS_Thread_TAG "[SS Thread] "


/*-----------------------------------------------------------------------------
 * MACROS
 */
#ifdef _DEBUG_
#define DEBUG_PRINT(x) printf x
#else
#define DEBUG_PRINT(x) \
    do {               \
    } while(0)
#endif


/*-----------------------------------------------------------------------------
 * TYPE DEFINITIONS
 */
typedef struct _FileMapping_
{
    int fd_;
    void* addr_;
    size_t size_;
    size_t size_pages_;
    unsigned char* page_status_;
} FileMapping;

typedef struct _PageSequence_
{
    size_t offset_;
    size_t length_;
} PageSequence;

typedef struct _CachedFile_
{
    int fd_;
    size_t size_;
    size_t size_pages_;
    size_t resident_memory_;
    DynArray resident_page_sequences_;
} CachedFile;

typedef struct _FillUpProcess_
{
    pid_t pid_;
    size_t fillup_size_;
} FillUpProcess;

typedef struct _AttackEvictionSet_
{
    FileMapping mapping_;
    size_t initialise_samples_;
    size_t initialise_max_runs_;
} AttackEvictionSet;

typedef struct _AttackWorkingSet_
{
    int evaluation_ : 1;
    int eviction_ignore_evaluation_ : 1;
    int64_t unused_ : 62; // align to 8bytes
    
    char** search_paths_;
    size_t mem_in_ws_;
    size_t tmp_mem_in_ws_;
    List resident_files_;
    List non_resident_files_;
    List tmp_resident_files_;
    List tmp_non_resident_files_;
    size_t ps_add_threshold_;
    size_t access_thread_count_;
    size_t access_threads_per_core_;
    DynArray access_threads_;
    struct timespec access_sleep_time_;
    struct timespec evaluation_sleep_time_;
    size_t profile_update_all_x_evaluations_;
} AttackWorkingSet;

typedef struct _AttackBlockingSet_
{
    char *meminfo_file_path_;
    DynArray fillup_processes_;
    size_t def_fillup_size_;
    size_t min_available_mem_;
    size_t max_available_mem_;
    struct timespec evaluation_sleep_time_;
    sem_t initialised_sem_;
} AttackBlockingSet;

typedef struct _PageAccessThreadData_
{
    pthread_mutex_t resident_files_lock_;
    List resident_files_;
    struct timespec sleep_time_;
    int running_;
    pthread_t tid_;
    pthread_attr_t thread_attr_;
} PageAccessThreadData;

typedef struct _CovertChannel_
{
    int use_attack_ws_ : 1;
    int use_attack_bs_ : 1;
    int mlock_self_ : 1;
    int64_t unused : 61; // align to 8byte

    AttackEvictionSet eviction_set_;
    AttackWorkingSet working_set_;
    pthread_t ws_manager_thread_;
    size_t mincore_check_all_x_bytes_;

    AttackBlockingSet blocking_set_;
    pthread_t bs_manager_thread_;

    FileMapping covert_file_mapping_;

    struct timespec sample_wait_time_;
} CovertChannel;


/*-----------------------------------------------------------------------------
 * FUNCTION PROTOTYPES
 */

// helper functions for custom datatypes
void initFileMapping(FileMapping *file_mapping);
void closeFileMapping(void *arg);
int initCachedFile(CachedFile *cached_file);
void closeCachedFile(void* arg);
void closeCachedFileArrayFreeOnly(void *arg);
void initFillUpProcess(FillUpProcess *fp);
void closeFillUpProcess(void *arg);
void closeThread(void *arg);
void initAttackEvictionSet(AttackEvictionSet *es);
void closeAttackEvictionSet(AttackEvictionSet *es);
int initAttackWorkingSet(AttackWorkingSet *ws);
void closeAttackWorkingSet(AttackWorkingSet *ws);
int initAttackBlockingSet(AttackBlockingSet *bs);
void closeAttackBlockingSet(AttackBlockingSet *bs);
void initPageAccessThreadData(PageAccessThreadData *ps_access_thread_data);
void closePageAccessThreadData(void *arg);
int initCovertChannel(CovertChannel *covert_channel);
void exitCovertChannel(CovertChannel *covert_channel);


// covert_channel function related
void configCovertChannel(CovertChannel *covert_channel);
int createRandomFile(char *filename, size_t ram_size);
int profileAttackWorkingSet(AttackWorkingSet *ws, char *covert_file_path);
int profileResidentPageSequences(CachedFile* current_cached_file, size_t ps_add_threshold);
int pageSeqCmp(void *node, void *data);
int blockRAM(AttackBlockingSet *bs, size_t fillup_size);
void releaseRAM(AttackBlockingSet *bs, size_t release_size);
void releaseRAMCb(void *arg1, void *arg2);
size_t evictMappedPages(CovertChannel *covert_channel);
void* bsManagerThread(void *arg);
size_t parseAvailableMem(char *meminfo_file_path);
void* wsManagerThread(void *arg);
void preparePageAccessThreadData(AttackWorkingSet *ws);
int reevaluateWorkingSet(AttackWorkingSet *ws);
int reevaluateWorkingSetList(List *cached_file_list, AttackWorkingSet *ws);
void* pageAccessThread(void *arg);
size_t getMappingCount(const unsigned char *status, size_t size_in_pages);
size_t getBitDiffCount(unsigned char *data, unsigned char *reference, size_t size);
void send(char *message, CovertChannel *covert_channel);
void receive(char *message, CovertChannel *covert_channel);
void usageError(char *app_name);


/*-----------------------------------------------------------------------------
 * GLOBAL VARIABLES
 */
static int running = 1;
static int eviction_running = 0;
static int used_cpus = 0;
static int MAX_CPUS = 0;
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
    // __ATOMIC_RELAXED = no thread ordering constraints
    __atomic_store_n(&running, 0, __ATOMIC_RELAXED);
}


/*-----------------------------------------------------------------------------
 * CODE
 */
int main(int argc, char* argv[])
{
    // general variables
    struct sysinfo system_info;
    struct sigaction quit_act = { 0 };
    int return_value = 0;

    // variables used for processing command line arguments
    CmdLineConf cmd_line_conf = 
    {
      .mandatory_args_count_ = MANDATORY_ARGS,
      .switches_count_ = SWITCHES_COUNT,
      .switches_ = SWITCHES_STR,
      .switches_arg_count_ = SWITCHES_ARG_COUNT
    };
    CmdLineParsed parsed_cmd_line;
    int mode = 0;

    // variables necessary for general covert channel function
    struct stat obj_stat;
    CovertChannel covert_channel = { 0 };
    FileMapping self_mapping = { 0 };
    cpu_set_t cpu_mask;
    pthread_attr_t thread_attr;
    char covert_file_path[PATH_MAX] = {0};
    pid_t sender_pid = 0, receiver_pid = 0;
    sem_t *sender_ready = NULL, *receiver_ready = NULL, *send_now = NULL;
    char *message = NULL;
    char *tst_msg = NULL, *rcvd_msg = NULL;
    int random_fd = 0, null_fd = 0;
    volatile uint8_t access = 0;

    // variables used for statistics
    FILE *tr_meas_file = NULL;
    struct timespec request_start, request_end;
    size_t elapsed_time_ns = 0;
    double tr_kb_sum = 0;
    size_t bit_error_count = 0, bit_error_sum = 0;


    // process command line arguments
    if(parseCmdArgs(&argv[1], argc - 1, &cmd_line_conf, &parsed_cmd_line) < 0) 
    {
        usageError(argv[0]);
        goto error;
    }
    for(int i = 0; i < cmd_line_conf.switches_count_; i++)
    {
	  if(parsed_cmd_line.switch_states_[i])
	  {
        if(mode == 0)
		{
		  mode = i;
		}
		else 
		{
			usageError(argv[0]);
			goto error;	
		}
      }		
	}


    // initialise random generator
    srand(time(NULL));


    // get number of cpus
    MAX_CPUS = get_nprocs();
    printf(INFO "%d CPUs available...\n", MAX_CPUS);
    

    // register signal handler for quiting the program by SRTG+C
    quit_act.sa_handler = quitHandler;
    return_value = sigaction(SIGINT, &quit_act, NULL);
    return_value += sigaction(SIGQUIT, &quit_act, NULL);
    return_value += sigaction(SIGUSR1, &quit_act, NULL);
    if(return_value != 0)
    {
        printf(FAIL "Error at registering signal handlers...\n");
        goto error;
    }


    // initialising covert_channel structure
    if(initCovertChannel(&covert_channel) != 0)
    {
        printf(FAIL "Error at initialising covert_channel configuration...\n");
        goto error;
    }

    // sample configuration
    configCovertChannel(&covert_channel);


    // get system information
    return_value = sysinfo(&system_info);
    if(return_value != 0)
    {
        printf(FAIL "Error (%s) at fetching system information...\n", strerror(errno));
        goto error;
    }
    printf(INFO "Total usable ram: %zu\n", system_info.totalram);

    // get system page size
    PAGE_SIZE = sysconf(_SC_PAGESIZE);
    if(PAGE_SIZE == -1)
    {
        printf(FAIL "Error (%s) at syscconf...\n", strerror(errno));
        goto error;
    }
    printf(INFO "System page size: %zu\n", PAGE_SIZE);


    // optional: mlock self
    if(covert_channel.mlock_self_)
    {
        // open self
        self_mapping.fd_ = open(argv[0], O_RDONLY);
        if(self_mapping.fd_ < 0)
        {
            printf(FAIL "Error (%s) at opening self (%s) ...\n", strerror(errno), argv[0]);
            goto error;
        }

        // get stat about self
        return_value = fstat(self_mapping.fd_, &obj_stat);
        if(return_value != 0)
        {
            printf(FAIL "Error (%s) at fstat for %s...\n", strerror(errno), argv[0]);
            goto error;
        }

        // map self
        self_mapping.size_ = obj_stat.st_size;
        self_mapping.size_pages_ = (obj_stat.st_size + PAGE_SIZE - 1) / PAGE_SIZE;
        // map binary as private, readable and executable
        self_mapping.addr_ =
            mmap(NULL, self_mapping.size_, PROT_READ | PROT_EXEC, MAP_PRIVATE, self_mapping.fd_, 0);
        if(self_mapping.addr_ == MAP_FAILED)
        {
            printf(FAIL "Error (%s) at mmap of object...\n", strerror(errno));
            goto error;
        }

        // mlock self
        mlock(self_mapping.addr_, self_mapping.size_);
    }


    if(mode == TEST_SWITCH)
    {
        printf(INFO "Starting performance test mode...\n");
        random_fd = open(RANDOM_SOURCE, O_RDONLY);
        null_fd = open(NULL_PATH, O_WRONLY);
        if(random_fd < 0 || null_fd < 0)
        {
            printf(FAIL "Error at opening /dev/urandom or /dev/null...\n");
            goto error;
        }

        sender_ready = mmap(NULL, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        receiver_ready = mmap(NULL, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        send_now = mmap(NULL, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if(sender_ready == MAP_FAILED || receiver_ready == MAP_FAILED || send_now == MAP_FAILED)
        {
            printf(FAIL "Error at mmap for memory for semaphores...\n");
            goto error;
        }

        sem_init(sender_ready, 1,  0);
        sem_init(receiver_ready, 1,  0);
        sem_init(send_now, 1,  0);
        tst_msg = mmap(NULL, MESSAGE_SIZE*sizeof(char), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        rcvd_msg = mmap(NULL, MESSAGE_SIZE*sizeof(char), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if(tst_msg == MAP_FAILED || rcvd_msg == MAP_FAILED)
        {
            printf(FAIL "Error at mmap for memory for tst_msg or rcvd_msg...\n");
            goto error;
        }

        // preparing test data
        /*if(read(random_fd, tst_msg, MESSAGE_SIZE) != MESSAGE_SIZE) 
        {
            printf(WARNING "Partial read from %s.\n", RANDOM_SOURCE);
        }*/

        // start sender process
        printf(INFO "Starting sender process...\n");
        sender_pid = fork();
        if (sender_pid < 0)
        {
            printf(FAIL "Error (%s) at fork...\n", strerror(errno));
            goto error;
        }
        if(sender_pid == 0)
        {
            dup2(null_fd, STDOUT_FILENO);
            mode = SEND_SWITCH;
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
        else if(receiver_pid == 0)
        {
            dup2(null_fd, STDOUT_FILENO);
            mode = RECEIVE_SWITCH;
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
        for (; run < TEST_SWITCH_RUNS && running; run++)
        {
            // preparing test data
            if(read(random_fd, tst_msg, MESSAGE_SIZE) != MESSAGE_SIZE) 
            {
                printf(WARNING "Partial read from %s.\n", RANDOM_SOURCE);
            }
            
            clock_gettime(CLOCK_REALTIME, &request_start);
            sem_post(send_now);
            sem_wait(receiver_ready);
            clock_gettime(CLOCK_REALTIME, &request_end);

            elapsed_time_ns = (request_end.tv_sec - request_start.tv_sec) * 1000000000 +
                              (request_end.tv_nsec - request_start.tv_nsec);

            tr_kb_sum += ((double) MESSAGE_SIZE / elapsed_time_ns) * 1000000;

            printf(INFO "Run %zu, duration: %zuns...\n", run, elapsed_time_ns);

            bit_error_count = getBitDiffCount((unsigned char*) tst_msg, (unsigned char*) rcvd_msg, MESSAGE_SIZE);
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

    // allocate memory for message
    message = malloc(MESSAGE_SIZE * sizeof(char));
    if (message == NULL)
    {
        printf(FAIL "Error (%s) at malloc...\n", strerror(errno));
        goto error;
    }

    // create covert channel file if it doesn't exist
    return_value = createRandomFile(parsed_cmd_line.mandatory_args_[COVERT_FILENAME_ARG], COVERT_FILE_SIZE);
    if(return_value != 0)
    {
        printf(FAIL "Error at creating covert file...\n");
        goto error;
    }

    // map covert file
    covert_channel.covert_file_mapping_.fd_ = open(parsed_cmd_line.mandatory_args_[COVERT_FILENAME_ARG], O_RDONLY);
    if(covert_channel.covert_file_mapping_.fd_ < 0)
    {
        printf(FAIL "Error (%s) at opening self (%s) ...\n", strerror(errno), parsed_cmd_line.mandatory_args_[COVERT_FILENAME_ARG]);
        goto error;
    }

    // get stat about covert file
    return_value = fstat(covert_channel.covert_file_mapping_.fd_, &obj_stat);
    if(return_value != 0)
    {
        printf(FAIL "Error (%s) at fstat for %s...\n", strerror(errno), parsed_cmd_line.mandatory_args_[COVERT_FILENAME_ARG]);
        goto error;
    }

    // map covert file
    covert_channel.covert_file_mapping_.size_ = obj_stat.st_size;
    covert_channel.covert_file_mapping_.size_pages_ = (obj_stat.st_size + PAGE_SIZE - 1) / PAGE_SIZE;
    // map binary as private, readable and executable
    covert_channel.covert_file_mapping_.addr_ =
        mmap(NULL, covert_channel.covert_file_mapping_.size_, PROT_READ | PROT_EXEC, MAP_PRIVATE, covert_channel.covert_file_mapping_.fd_, 0);
    if(covert_channel.covert_file_mapping_.addr_ == MAP_FAILED)
    {
        printf(FAIL "Error (%s) at mmap of object...\n", strerror(errno));
        goto error;
    }
    
    covert_channel.covert_file_mapping_.page_status_ = malloc(covert_channel.covert_file_mapping_.size_pages_);
        if(covert_channel.covert_file_mapping_.page_status_ == NULL) {
            printf(FAIL "Error (%s) at malloc...\n", strerror(errno));
            goto error;
        }

    // set access to random (try to prevent readahead)
    posix_fadvise(covert_channel.covert_file_mapping_.fd_, 0, 0, POSIX_FADV_RANDOM);
    madvise(covert_channel.covert_file_mapping_.addr_, covert_channel.covert_file_mapping_.size_, MADV_RANDOM);


    // send mode
    if(mode == SEND_SWITCH)
    {
        printf(INFO "Initialising send mode...\n");
        
        //  limit execution on CPU 0 by default
		CPU_ZERO(&cpu_mask);
		CPU_SET(0, &cpu_mask);
		sched_setaffinity(0, sizeof(cpu_mask), &cpu_mask);
		used_cpus = (used_cpus + HYPERTHREADS_PER_CORE < MAX_CPUS) ? used_cpus + HYPERTHREADS_PER_CORE : used_cpus;

		// later used to set thread affinity
		pthread_attr_init(&thread_attr);


        // create eviction file if it doesn't exist
        return_value = createRandomFile(EVICTION_FILENAME, system_info.totalram);
        if(return_value != 0)
        {
            printf(FAIL "Error at creating eviction file...\n");
            goto error;
        }

        // map eviction memory
        covert_channel.eviction_set_.mapping_.fd_ = open(EVICTION_FILENAME, O_RDONLY | O_NOATIME);
        if(covert_channel.eviction_set_.mapping_.fd_ < 0)
        {
            printf(FAIL "Error (%s) at opening eviction file...\n", strerror(errno));
            goto error;
        }

        covert_channel.eviction_set_.mapping_.size_ = system_info.totalram;
        covert_channel.eviction_set_.mapping_.size_pages_ =
            (covert_channel.eviction_set_.mapping_.size_ + PAGE_SIZE - 1) / PAGE_SIZE;

        // map the eviction file as private and readable only
        covert_channel.eviction_set_.mapping_.addr_ = mmap(NULL, covert_channel.eviction_set_.mapping_.size_,
                PROT_READ | PROT_EXEC, MAP_PRIVATE, covert_channel.eviction_set_.mapping_.fd_, 0);
        if(covert_channel.eviction_set_.mapping_.addr_ == MAP_FAILED)
        {
            printf(FAIL "Error (%s) at mmap of eviction file...\n", strerror(errno));
            goto error;
        }

        // activate readahead of eviction set pages
        //posix_fadvise(covert_channel.eviction_set_.mapping_.fd_, 0, 0, POSIX_FADV_WILLNEED);
        //madvise(covert_channel.eviction_set_.mapping_.addr_, covert_channel.eviction_set_.mapping_.size_, MADV_WILLNEED);

        if(covert_channel.use_attack_ws_)
        {
            realpath(parsed_cmd_line.mandatory_args_[COVERT_FILENAME_ARG], covert_file_path);
            printf(PENDING "Profiling working set...\n");
            if(profileAttackWorkingSet(&covert_channel.working_set_, covert_file_path) != 0)
            {
                goto error;
            }
			printf(INFO "%zu files with %zu mapped bytes of sequences bigger than %zu pages are currently resident in memory.\n",
                   covert_channel.working_set_.resident_files_.count_, covert_channel.working_set_.mem_in_ws_, covert_channel.working_set_.ps_add_threshold_);
        }

		// next thread(s) by default on different core
		CPU_ZERO(&cpu_mask);
		CPU_SET(0, &cpu_mask);
		sched_setaffinity(0, sizeof(cpu_mask), &cpu_mask);
		used_cpus = (used_cpus + HYPERTHREADS_PER_CORE < MAX_CPUS) ? used_cpus + HYPERTHREADS_PER_CORE : used_cpus;

        // start bs manager thread if wanted
        if(covert_channel.use_attack_bs_ && pthread_create(&covert_channel.bs_manager_thread_, NULL, bsManagerThread, &covert_channel.blocking_set_) != 0)
        {
            printf(FAIL "Error (%s) at creating blocking set manager thread...\n", strerror(errno));
        }
        
        // start ws manager thread if wanted
        if(covert_channel.use_attack_ws_ && pthread_create(&covert_channel.ws_manager_thread_, NULL, wsManagerThread, &covert_channel.working_set_) != 0)
        {
            printf(FAIL "Error (%s) at creating working set manager thread...\n", strerror(errno));
        }


        // wait till RAM is blocked
        sem_wait(&covert_channel.blocking_set_.initialised_sem_);
        
        // flush message file
        evictMappedPages(&covert_channel);
    
        // access ack
        access += *((uint8_t *) covert_channel.covert_file_mapping_.addr_ + ACK_PAGE_OFFSET*PAGE_SIZE);

        printf(OK "Ready...\n");

        if(sender_ready)
        {
            sem_post(sender_ready);
        }

        while(running)
        {
            if(tst_msg)
            {
                sem_wait(send_now);
                send(tst_msg, &covert_channel);
            }
            else
            {
                memset(message, 0, MESSAGE_SIZE);
                fgets(message, MESSAGE_SIZE, stdin);
                send(message, &covert_channel);
            }
        }
    }
    else if(mode == RECEIVE_SWITCH)
    {
        printf(INFO"Initialsing receive mode...\n");
        //  limit execution on CPU 2 by default
        CPU_ZERO(&cpu_mask);
        CPU_SET(2, &cpu_mask);
        sched_setaffinity(0, sizeof(cpu_mask), &cpu_mask);
        printf(OK"Ready...\n");

        if(receiver_ready)
        {
            sem_post(receiver_ready);
        }

        while(running)
        {
            memset(message, 0, MESSAGE_SIZE);

            if(rcvd_msg)
            {
                receive(rcvd_msg, &covert_channel);
                sem_post(receiver_ready);
            }
            else
            {
                receive(message, &covert_channel);
                printf("%s\n", message);
            }
        }
    }

    goto cleanup;

error:
    return_value = -1;

cleanup:

    pthread_attr_destroy(&thread_attr);

    exitCovertChannel(&covert_channel);
    if(covert_channel.mlock_self_)
    {
        closeFileMapping(&self_mapping);
    }

    free(message);

    if(mode == TEST_SWITCH)
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

	freeCmdLineParsed(&cmd_line_conf, &parsed_cmd_line);

    return return_value;
}



/*-----------------------------------------------------------------------------
 * HELPER FUNCTIONS FOR CUSTOM STRUCTS
 */


void initFileMapping(FileMapping* file_mapping)
{
    memset(file_mapping, 0, sizeof(FileMapping));
    file_mapping->fd_ = -1;
}


void closeFileMapping(void* arg)
{
    FileMapping *file_mapping = arg;

    if(file_mapping->addr_ != NULL)
    {
        munmap(file_mapping->addr_, file_mapping->size_);
        file_mapping->addr_ = NULL;
    }
    if(file_mapping->fd_ >= 0)
    {
        close(file_mapping->fd_);
        file_mapping->fd_ = -1;
    }
    free(file_mapping->page_status_);
}

int initCachedFile(CachedFile *cached_file)
{
    memset(cached_file, 0, sizeof(CachedFile));
    cached_file->fd_ = -1;
    if(!dynArrayInit(&cached_file->resident_page_sequences_, sizeof(PageSequence), ARRAY_INIT_CAP))
    {
        return -1;
    }

    return 0;
}


void closeCachedFile(void* arg)
{
    CachedFile *cached_file = arg;

    if(cached_file->fd_ >= 0)
    {
        close(cached_file->fd_);
        cached_file->fd_ = -1;
    }
    dynArrayDestroy(&cached_file->resident_page_sequences_, NULL);
}


void closeCachedFileArrayFreeOnly(void* arg)
{
    CachedFile *cached_file = arg;
    dynArrayDestroy(&cached_file->resident_page_sequences_, NULL);
}


void initFillUpProcess(FillUpProcess* fp)
{
    memset(fp, 0, sizeof(FillUpProcess));
}


void closeFillUpProcess(void *arg)
{
    FillUpProcess* fp = arg;

    if(fp->pid_ != 0)
    {
        kill(fp->pid_, SIGKILL);
    }

    fp->pid_ = 0;
}


void closeThread(void *arg)
{
    pthread_t* thread = arg;

    pthread_join(*thread, NULL);
}


void initAttackEvictionSet(AttackEvictionSet* es)
{
    memset(es, 0, sizeof(AttackEvictionSet));

    initFileMapping(&es->mapping_);
}


void closeAttackEvictionSet(AttackEvictionSet* es)
{
    closeFileMapping(&(es->mapping_));
}


int initAttackWorkingSet(AttackWorkingSet* ws)
{
    memset(ws, 0, sizeof(AttackWorkingSet));
    if(!dynArrayInit(&ws->access_threads_, sizeof(PageAccessThreadData), ARRAY_INIT_CAP))
    {
        return -1;
    }
    listInit(&ws->resident_files_, sizeof(CachedFile));
    listInit(&ws->non_resident_files_, sizeof(CachedFile));
    listInit(&ws->tmp_resident_files_, sizeof(CachedFile));
    listInit(&ws->tmp_non_resident_files_, sizeof(CachedFile));

    return 0;
}


void closeAttackWorkingSet(AttackWorkingSet* ws)
{
    dynArrayDestroy(&ws->access_threads_, closePageAccessThreadData);
    listDestroy(&ws->resident_files_, closeCachedFile);
    listDestroy(&ws->non_resident_files_, closeCachedFile);
    listDestroy(&ws->tmp_resident_files_, closeCachedFile);
    listDestroy(&ws->tmp_non_resident_files_, closeCachedFile);
}


int initAttackBlockingSet(AttackBlockingSet* bs)
{
	memset(bs, 0, sizeof(AttackBlockingSet));
    if(!dynArrayInit(&bs->fillup_processes_, sizeof(pid_t), ARRAY_INIT_CAP))
    {
        return -1;
    }

    sem_init(&bs->initialised_sem_, 0, 0);

    return 0;
}


void closeAttackBlockingSet(AttackBlockingSet* bs)
{
    dynArrayDestroy(&bs->fillup_processes_, closeFillUpProcess);

    sem_destroy(&bs->initialised_sem_);
}


void initPageAccessThreadData(PageAccessThreadData *page_access_thread_data)
{
    memset(page_access_thread_data, 0, sizeof(PageAccessThreadData));
    pthread_mutex_init(&page_access_thread_data->resident_files_lock_, NULL);
}


void closePageAccessThreadData(void *arg)
{
    PageAccessThreadData *page_access_thread_data = arg;

    if(page_access_thread_data->running_)
    {
        __atomic_store_n(&page_access_thread_data->running_, 0, __ATOMIC_RELAXED);
        pthread_join(page_access_thread_data->tid_, NULL);
        pthread_attr_destroy(&page_access_thread_data->thread_attr_);
    }
}


int initCovertChannel(CovertChannel* covert_channel)
{
    memset(covert_channel, 0, sizeof(CovertChannel));

    initAttackEvictionSet(&covert_channel->eviction_set_);

    if(initAttackWorkingSet(&covert_channel->working_set_) != 0)
    {
        return -1;
    }

    if(initAttackBlockingSet(&covert_channel->blocking_set_) != 0)
    {
        return -1;
    }

    initFileMapping(&covert_channel->covert_file_mapping_);

    return 0;
}


void exitCovertChannel(CovertChannel* covert_channel)
{
    pthread_join(covert_channel->bs_manager_thread_, NULL);
    closeAttackBlockingSet(&covert_channel->blocking_set_);
    pthread_join(covert_channel->ws_manager_thread_, NULL);

    // in reverse close remaining files, unmap and free memory
    closeFileMapping(&covert_channel->covert_file_mapping_);
    closeAttackWorkingSet(&covert_channel->working_set_);
    closeAttackEvictionSet(&covert_channel->eviction_set_);
}



/*-----------------------------------------------------------------------------
 * FUNCTIONS RELATED TO COVERT CHANNEL
 */

void configCovertChannel(CovertChannel *covert_channel)
{
    covert_channel->use_attack_ws_ |= DEF_USE_ATTACK_WS;
    covert_channel->use_attack_bs_ |= DEF_USE_ATTACK_BS;
    covert_channel->mlock_self_ |= DEF_MLOCK_SELF;

    covert_channel->working_set_.evaluation_ |= DEF_WS_EVALUATION;
    covert_channel->working_set_.eviction_ignore_evaluation_ |= DEF_WS_EVICTION_IGNORE_EVALUATION;
    covert_channel->working_set_.search_paths_ = DEF_WS_SEARCH_PATHS;
    covert_channel->working_set_.ps_add_threshold_ = DEF_WS_PS_ADD_THRESHOLD;
    covert_channel->working_set_.access_thread_count_ = DEF_WS_ACCESS_THREAD_COUNT;
    covert_channel->working_set_.access_threads_per_core_ = DEF_WS_ACCESS_THREADS_PER_CORE;
    covert_channel->working_set_.access_sleep_time_.tv_sec = DEF_WS_ACCESS_SLEEP_TIME_S;
    covert_channel->working_set_.access_sleep_time_.tv_nsec = DEF_WS_ACCESS_SLEEP_TIME_NS;
    covert_channel->working_set_.evaluation_sleep_time_.tv_sec = DEF_WS_EVALUATION_SLEEP_TIME_S;
    covert_channel->working_set_.evaluation_sleep_time_.tv_nsec = DEF_WS_EVALUATION_SLEEP_TIME_NS;
    covert_channel->working_set_.profile_update_all_x_evaluations_ = DEF_WS_PROFILE_UPDATE_ALL_X_EVALUATIONS;

    covert_channel->mincore_check_all_x_bytes_ = DEF_MINCORE_CHECK_ALL_X_BYTES;

    covert_channel->blocking_set_.meminfo_file_path_ = DEF_BS_MEMINFO_FILE_PATH;
    covert_channel->blocking_set_.def_fillup_size_ = DEF_BS_FILLUP_SIZE;
    covert_channel->blocking_set_.min_available_mem_ = DEF_BS_MIN_AVAILABLE_MEM;
    covert_channel->blocking_set_.max_available_mem_ = DEF_BS_MAX_AVAILABLE_MEM;
    covert_channel->blocking_set_.evaluation_sleep_time_.tv_sec = DEF_BS_EVALUATION_SLEEP_TIME_S;
    covert_channel->blocking_set_.evaluation_sleep_time_.tv_nsec = DEF_BS_EVALUATION_SLEEP_TIME_NS;

    covert_channel->sample_wait_time_.tv_sec = 0;
    covert_channel->sample_wait_time_.tv_nsec = DEF_SAMPLE_WAIT_TIME_NS;
}


int createRandomFile(char* filename, size_t size)
{
    int fd;
    struct stat file_stat;
    struct statvfs filesys_stat;
    char cwd[PATH_MAX] = { 0 };

	// open file or if already exists check if current size, else overwrite
    fd = open(filename, O_CREAT | O_WRONLY | O_EXCL, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if(fd < 0)
    {
        if(errno != EEXIST)
        {
            return -1;
        }

        if(stat(filename, &file_stat) != 0)
        {
            printf(FAIL "Error (%s) at stat: %s...\n", strerror(errno), filename);
            return -1;
        }

        if(file_stat.st_size < size)
        {
            close(fd);
            fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
            if(fd < 0)
            {
                return -1;
            }
        }
        else
        {
            printf(INFO "File %s already exists...\n", filename);
            return 0;
        }
    }

    // create new file
    printf(PENDING "Creating %zu MB random file. This might take a while...\n", size / 1024 / 1024);
    if(getcwd(cwd, sizeof(cwd)) == NULL)
    {
        printf(FAIL "Error (%s) at getcwd...\n", strerror(errno));
        return -1;
    }

    if(statvfs(cwd, &filesys_stat) != 0)
    {
        printf(FAIL "Error (%s) at statvfs...\n", strerror(errno));
        return -1;
    }

    // sanity checks
    size_t free_disk = filesys_stat.f_bsize * filesys_stat.f_bavail;
    if(free_disk < size)
    {
        printf(FAIL "Free disk space must be greater or equal memory size!\n");
        return -1;
    }

    // try fallocate first, if it fails fall back to the much slower file copy
    if(fallocate(fd, 0, 0, size) != 0)
    {
        // fallocate failed, fall back to creating eviction file from /dev/urandom
        close(fd);

        FILE* rnd_file = fopen(RANDOM_SOURCE, "rb");
        if(rnd_file == NULL)
        {
            printf(FAIL "Error (%s) at fopen: %s...\n", strerror(errno), RANDOM_SOURCE);
            return -1;
        }
        FILE* target_file = fopen(filename, "wb");
        if(target_file == NULL)
        {
            printf(FAIL "Error (%s) at fopen: %s...\n", strerror(errno), filename);
            return -1;
        }
        size_t bs = FILE_COPY_BS;
        size_t rem = size;
        
        char* block = malloc(bs);
        if(block == NULL)
        {
            printf(FAIL "Error (%s) at malloc for block...\n", strerror(errno));
            return -1;
        }

        while(rem)
        {
            if(fread(block, bs, 1, rnd_file) != 1)
            {
                printf(FAIL "Error (%s) at fread: %s...\n", strerror(errno), RANDOM_SOURCE);
                fclose(rnd_file);
                fclose(target_file);
                free(block);
                return -1;
            }
            if(fwrite(block, bs, 1, target_file) != 1)
            {
                printf(FAIL "Error (%s) at fwrite: %s...\n", strerror(errno), filename);
                fclose(rnd_file);
                fclose(target_file);
                free(block);
                return -1;
            }
            if(rem >= bs)
            {
                rem -= bs;
            }
            else
            {
                rem = 0;
            }
        }

        free(block);
        fclose(rnd_file);
        fclose(target_file);
        free(block);
    }

    close(fd);
    return 0;
}


int profileAttackWorkingSet(AttackWorkingSet* ws, char* covert_file_path)
{
    FTS* fts_handle = NULL;
    FTSENT* current_ftsent = NULL;
    CachedFile current_cached_file = { 0 };
    size_t checked_files = 0;
    size_t memory_checked = 0;
    size_t mem_in_ws = 0;
    int ret = 0;

    // use fts to traverse over all files in the searchpath
    fts_handle = fts_open(ws->search_paths_, FTS_PHYSICAL, NULL);
    if(fts_handle == NULL)
    {
        printf(FAIL "Error (%s) at fts_open...\n", strerror(errno));
        return -1;
    }

    while(running)
    {
        current_ftsent = fts_read(fts_handle);
        // error at traversing files
        if(current_ftsent == NULL && errno)
        {
            // catch too many open files error (end gracefully)
            if(errno == EMFILE)
            {
                printf(WARNING "Too many open files at fts_read, ignoring rest of files...\n");
                break;
            }

            DEBUG_PRINT((DEBUG "Error (%s) at fts_read...\n", strerror(errno)));
            goto error;
        }
        // end
        else if(current_ftsent == NULL)
        {
            break;
        }

        // regular file
        if(current_ftsent->fts_info == FTS_F)
        {
            DEBUG_PRINT((DEBUG "Found possible shared object: %s\n", current_ftsent->fts_path));

            // check if the shared object matches the target
            if(!strcmp(current_ftsent->fts_name, EVICTION_FILENAME) ||
                    !strcmp(current_ftsent->fts_path, covert_file_path))
            {
                DEBUG_PRINT((DEBUG "Shared object %s is the eviction file or target, skipping...\n", current_ftsent->fts_name));
                continue;
            }

            if(current_ftsent->fts_statp->st_size == 0)
            {
                DEBUG_PRINT((DEBUG "File %s has zero size skipping...\n", current_ftsent->fts_name));
                continue;
            }

            // prepare cached file object
            // ignore errors, try again
            if(initCachedFile(&current_cached_file) < 0)
            {
                DEBUG_PRINT((DEBUG "Error at initCachedFile...\n"));
                continue;
            }
            // open file, do not update access time (faster)
            // ignore errors, try again
            current_cached_file.fd_ = open(current_ftsent->fts_accpath, O_RDONLY | O_NOATIME);
            if(current_cached_file.fd_ < 0)
            {
                DEBUG_PRINT((DEBUG "Error (%s) at open: %s...\n", strerror(errno),
                             current_ftsent->fts_accpath));
                closeCachedFile(&current_cached_file);
                continue;
            }
            current_cached_file.size_ = current_ftsent->fts_statp->st_size;
            current_cached_file.size_pages_ = (current_cached_file.size_ + PAGE_SIZE - 1) / PAGE_SIZE;

            // parse page sequences
            // ignore errors, try again
            if(profileResidentPageSequences(&current_cached_file, ws->ps_add_threshold_) < 0)
            {
                printf(WARNING "Error at profileResidentPageSequences: %s...\n", current_ftsent->fts_accpath);
                closeCachedFile(&current_cached_file);
                continue;
            }

            // no page sequences -> close object
            if(current_cached_file.resident_page_sequences_.size_ == 0)
            {
                closeCachedFile(&current_cached_file);
            }
            // else add current cached file to cached files
            else
            {
                // ignore errors, try again
                if(!listAppendBack(&ws->resident_files_, &current_cached_file))
                {
                    closeCachedFile(&current_cached_file);
                    continue;
                }
            }

            checked_files++;
            memory_checked += current_cached_file.size_;
            mem_in_ws += current_cached_file.resident_memory_;
        }
    }


    ws->mem_in_ws_ = mem_in_ws;
    DEBUG_PRINT((DEBUG "Finished profiling loaded shared objects (%zu files checked, checked data %zu kB, used as working set %zu kB)!\n",
                 checked_files, memory_checked / 1024, mem_in_ws / 1024));

    goto cleanup;

error:
    ret = -1;
    listDestroy(&ws->resident_files_, closeCachedFile);
    closeCachedFile(&current_cached_file);

cleanup:

    fts_close(fts_handle);

    return ret;
}


int profileResidentPageSequences(CachedFile* current_cached_file, size_t ps_add_threshold)
{
    int ret = 0;
    void *mapping_addr = MAP_FAILED;
    unsigned char* page_status = NULL;
    PageSequence sequence = { 0 };

    // reset array size to zero
    dynArrayReset(&current_cached_file->resident_page_sequences_);
    // reset resident memory
    current_cached_file->resident_memory_ = 0;

    // advise random access to avoid readahead
    posix_fadvise(current_cached_file->fd_, 0, 0, POSIX_FADV_RANDOM);

    mapping_addr =
        mmap(NULL, current_cached_file->size_, PROT_READ | PROT_EXEC, MAP_PRIVATE, current_cached_file->fd_, 0);
    if(mapping_addr == MAP_FAILED)
    {
        DEBUG_PRINT((DEBUG "Error (%s) at mmap...\n", strerror(errno)));
        goto error;
    }

    // advise random access to avoid readahead
    // NOTE on linux actually posix_fadvise and madvise use the same internal functions so this is kind of redundant
    madvise(mapping_addr, current_cached_file->size_, MADV_RANDOM);


    page_status = malloc(current_cached_file->size_pages_);
    if(page_status == NULL)
    {
        DEBUG_PRINT((DEBUG "Error (%s) at malloc...\n", strerror(errno)));
        goto error;
    }

    if(mincore(mapping_addr, current_cached_file->size_, page_status) != 0)
    {
        DEBUG_PRINT((DEBUG "Error (%s) at mincore...\n", strerror(errno)));
        goto error;
    }


    // check for sequences and add them
    for(size_t p = 0; p < current_cached_file->size_pages_; p++)
    {
        if(page_status[p] & 1)
        {
            if(sequence.length_ == 0)
            {
                sequence.offset_ = p;
            }

            sequence.length_++;
        }
        else
        {
            // add sequence if longer than threshold
            if(sequence.length_ > ps_add_threshold)
            {
                // add sequence pages
                if(!dynArrayAppend(&current_cached_file->resident_page_sequences_, &sequence))
                {
                    DEBUG_PRINT((DEBUG "Error at dynArrayAppend...\n"));
                    goto error;
                }

                current_cached_file->resident_memory_ += sequence.length_ * PAGE_SIZE;
                DEBUG_PRINT((DEBUG "Added page sequence with page offset %zu and %zu pages\n",
                             sequence.offset_, sequence.length_));
                // reset sequence length
                sequence.length_ = 0;
            }
        }
    }
    // process last found sequence
    if(sequence.length_ > ps_add_threshold)
    {
        // add sequence pages
        if(!dynArrayAppend(&current_cached_file->resident_page_sequences_, &sequence))
        {
            DEBUG_PRINT((DEBUG "Error at dynArrayAppend...\n"));
            goto error;
        }

        current_cached_file->resident_memory_ += sequence.length_ * PAGE_SIZE;
        DEBUG_PRINT((DEBUG "Added page sequence with page offset %zu and %zu pages\n",
                     sequence.offset_, sequence.length_));

    }


    goto cleanup;
    
error:

    ret = -1;
    dynArrayDestroy(&current_cached_file->resident_page_sequences_, NULL);
    current_cached_file->resident_memory_ = 0;

cleanup:

    if(mapping_addr != MAP_FAILED)
    {
        munmap(mapping_addr, current_cached_file->size_);
    }
    free(page_status);

    return ret;
}


int pageSeqCmp(void* node, void* data)
{
    if(((PageSequence*)data)->length_ > ((PageSequence*)node)->length_)
    {
        return 1;
    }

    return 0;
}


int blockRAM(AttackBlockingSet* bs, size_t fillup_size)
{
    pid_t child_pid;
    void* fillup_mem;
    sem_t* sem;

    // create a shared semaphore
    sem = mmap(NULL, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if(sem == MAP_FAILED)
    {
        printf(FAIL BS_MGR_TAG "Error (%s) at mmap...\n", strerror(errno));
        return -1;
    }

    if(sem_init(sem, 1, 0))
    {
        printf(FAIL BS_MGR_TAG "Error (%s) at sem_init...\n", strerror(errno));
        return -1;
    }

    DEBUG_PRINT((DEBUG BS_MGR_TAG "Going to block %zu kB of physical memory, need %zu child processes...\n", fillup_size / 1024,
                 fillup_size / bs->def_fillup_size_));

    // round down - rather keep a bit more memory free
    for(size_t i = 1; i <= fillup_size / bs->def_fillup_size_; i++)
    {
        child_pid = fork();

        if(child_pid < 0)
        {
            printf(FAIL BS_MGR_TAG "Error (%s) at fork for block ram child..\n", strerror(errno));
            return -1;
        }
        else if(child_pid == 0)
        {
            // child
            DEBUG_PRINT(
                (DEBUG BS_MGR_TAG "New child %zu with %zu kB dirty memory spawned...\n", i, bs->def_fillup_size_ / 1024));

            fillup_mem = mmap(
                             NULL, bs->def_fillup_size_, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);

            if(fillup_mem == MAP_FAILED)
            {
                if(sem_post(sem) != 0)
                {
                    printf(FAIL BS_MGR_TAG "Error (%s) at sem_post...\n", strerror(errno));
				}

                printf(FAIL BS_MGR_TAG "Error (%s) mmap of blocking memory...\n", strerror(errno));
                exit(-1);
            }

            // write to fillup memory (unique contents -> no page deduplication)
            for(size_t m = 0; m < bs->def_fillup_size_; m += PAGE_SIZE)
            {
                *((size_t *) ((uint8_t *) fillup_mem + m)) = i * m;
            }

            // finished
            if(sem_post(sem) != 0)
            {
                printf(FAIL BS_MGR_TAG "Error (%s) at sem_post...\n", strerror(errno));
                exit(-1);
            }

            while(1)
            {
                // wait for signal
                pause();
            }
        }

        // parent
        // wait until child process has finished
        if(sem_wait(sem))
        {
            printf(FAIL BS_MGR_TAG "Error (%s) at sem_wait...\n", strerror(errno));
            return -1;
        }

        // error at dynArrayAppend <=> child could not be added
        if(!dynArrayAppend(&bs->fillup_processes_, &child_pid)) 
        {
            // kill child
            kill(child_pid, SIGKILL); 
            printf(FAIL BS_MGR_TAG "Error (%s) at dynArrayAppend...\n", strerror(errno));
            return -1;
        }
    }

    munmap(sem, sizeof(sem_t));
    return 0;
}


void releaseRAM(AttackBlockingSet* bs, size_t release_size)
{
    size_t released;

    DEBUG_PRINT((DEBUG BS_MGR_TAG "Releasing %zu kB of blocking memory\n", release_size / 1024));

    while(release_size > 0 && bs->fillup_processes_.size_ > 0)
    {
        dynArrayPop(&bs->fillup_processes_, releaseRAMCb, &released);
        release_size = (release_size > released) ? release_size - released : 0;
    }
}


void releaseRAMCb(void *arg1, void *arg2)
{
    FillUpProcess *fp = arg1;
    size_t *released = arg2;

    kill(fp->pid_, SIGKILL);
    *released = fp->fillup_size_;
}

size_t evictMappedPages(CovertChannel* covert_channel)
{
    volatile uint8_t tmp = 0;
    ssize_t accessed_mem = 0;
    size_t current_covert_mapped;

    // more aggressive readahead (done before), here experimentally
    //posix_fadvise(covert_channel->eviction_set_.mapping_.fd_, 0, 0, POSIX_FADV_WILLNEED);
    //madvise(covert_channel->eviction_set_.mapping_.addr_, covert_channel->eviction_set_.mapping_.size_, MADV_WILLNEED);

    // flag eviction running
    __atomic_store_n(&eviction_running, 1, __ATOMIC_RELAXED);


    mincore(covert_channel->covert_file_mapping_.addr_, covert_channel->covert_file_mapping_.size_, covert_channel->covert_file_mapping_.page_status_);
    current_covert_mapped = getMappingCount(covert_channel->covert_file_mapping_.page_status_, covert_channel->covert_file_mapping_.size_pages_);
    DEBUG_PRINT((DEBUG "%zu message pages still mapped\n", current_covert_mapped));

    while(current_covert_mapped > 0 && __atomic_load_n(&running, __ATOMIC_RELAXED))
    {
        for(size_t p = 0; current_covert_mapped > 0 && p < covert_channel->eviction_set_.mapping_.size_pages_ && __atomic_load_n(&running, __ATOMIC_RELAXED); p++)
        {

            tmp = *((uint8_t *) covert_channel->eviction_set_.mapping_.addr_ + (p) * PAGE_SIZE);
            accessed_mem += PAGE_SIZE;

            // check if pages are evicted
            if(accessed_mem % covert_channel->mincore_check_all_x_bytes_ == 0) 
            {
                if (mincore(covert_channel->covert_file_mapping_.addr_, covert_channel->covert_file_mapping_.size_, covert_channel->covert_file_mapping_.page_status_) < 0) 
                {
                    printf(FAIL "Error (%s) at mincore...\n", strerror(errno));
                }
                else 
                {
                    current_covert_mapped = getMappingCount(covert_channel->covert_file_mapping_.page_status_, covert_channel->covert_file_mapping_.size_pages_);
                    DEBUG_PRINT((DEBUG "%zu message pages still mapped\n", current_covert_mapped));
                }
            }
        }
    }

    __atomic_store_n(&eviction_running, 0, __ATOMIC_RELAXED);

    return accessed_mem;
}


void* bsManagerThread(void *arg)
{
    AttackBlockingSet* bs = arg;
    size_t available_mem = 0;
    size_t mem_diff = 0;
    // set goal for available mem in middle of allowed region
    size_t available_mem_goal = bs->min_available_mem_ + (bs->max_available_mem_ - bs->min_available_mem_) / 2;
    int initialised_sem_val = 0;

    while(__atomic_load_n(&running, __ATOMIC_RELAXED))
    {
        DEBUG_PRINT((DEBUG BS_MGR_TAG "BS manager thread running on core %d.\n", sched_getcpu()));
        available_mem = parseAvailableMem(bs->meminfo_file_path_) * 1024;
        DEBUG_PRINT((DEBUG BS_MGR_TAG "%zu kB of physical memory available\n", available_mem / 1024));
        //printf(DEBUG BS_MGR_TAG "%zu kB of physical memory available\n", available_mem / 1024);
        
        if(available_mem < bs->min_available_mem_)
        {
            mem_diff = available_mem_goal - available_mem;
            printf(BS_MGR_TAG "Too less physical memory available, releasing %zu kB...\n", mem_diff / 1024);
            releaseRAM(bs, mem_diff);
        }
        else if(available_mem > bs->max_available_mem_)
        {
            // /4 * 3 for slower convergence
            mem_diff = (available_mem - available_mem_goal) / 4 * 3;

            if(mem_diff >= bs->def_fillup_size_)
            {
                printf(BS_MGR_TAG "Too much physical memory available, blocking %zu kB...\n", mem_diff / 1024);
                blockRAM(bs, mem_diff);
            }
        }
        else
        {
            if(sem_getvalue(&bs->initialised_sem_, &initialised_sem_val) == 0 && initialised_sem_val == 0)
            {
                if(sem_post(&bs->initialised_sem_) < 0)
                {
                    printf(BS_MGR_TAG FAIL "Error (%s) at sem_post.", strerror(errno));
                }
            }
        }

        nanosleep(&bs->evaluation_sleep_time_, NULL);
    }

    return NULL;
}


size_t parseAvailableMem(char *meminfo_file_path)
{
    FILE *meminfo_file = NULL;
    char line[LINE_MAX] = {0};
    char *available_mem_str = NULL;
    char *conversion_end = NULL;
    // in case of error SIZE_T_MAX is reported as available memory to trigger no action
    size_t available_mem = (size_t) -1;


    // open meminfo file
    meminfo_file = fopen(meminfo_file_path, "r");
    if(!meminfo_file)
    {
        printf(WARNING BS_MGR_TAG "Available memory could not be parsed!\n");
        printf(WARNING BS_MGR_TAG "Returning SIZE_MAX!\n");
        return available_mem;
    }


    // canary to see if line was longer as buffer
    line[IN_LINE_MAX - 1] = 'c';
    while(fgets(line, IN_LINE_MAX, meminfo_file))
    {
        // skip lines longer than 255
        if(line[IN_LINE_MAX - 1] == '\0')
        {
            continue;
        }

        if(strstr(line, MEMINFO_AVAILABLE_MEM_TAG) != NULL)
        {
            for(size_t c = strlen(MEMINFO_AVAILABLE_MEM_TAG);  line[c] != 0; c++)
            {
                if(isdigit(line[c]))
                {
                    if(available_mem_str == NULL)
                    {
                        available_mem_str = line + c;
                    }
                }
                else if(available_mem_str != NULL)
                {
                    line[c] = 0;
                    break;
                }
            }

            available_mem = strtoul(available_mem_str, &conversion_end, 10);
            if((available_mem_str != NULL && *available_mem_str == 0) || *conversion_end != 0 || errno == ERANGE)
            {
                available_mem_str = NULL;
                break;
            }

            break;
        }
    }


    if(!available_mem_str)
    {
        printf(WARNING BS_MGR_TAG "Available memory could not be parsed!\n");
        printf(WARNING BS_MGR_TAG "Returning SIZE_MAX!\n");
    }

    fclose(meminfo_file);

    return available_mem;
}


// TODO Maybe update profile after certain amount of time.
void* wsManagerThread(void *arg)
{
    AttackWorkingSet* ws = arg;
    size_t runs_since_last_profile_update = 0;
    void *ret = NULL;
    cpu_set_t cpu_mask;
    List tmp_list_swap1;
    List tmp_list_swap2;
    size_t tmp_size_t;


    //  reserve space for access thread data structures
    if(dynArrayResize(&ws->access_threads_, ws->access_thread_count_) == NULL)
    {
        printf(FAIL WS_MGR_TAG "Could not reserve memory...\n");
        goto error;
    }
    for(size_t t = 0; t < ws->access_thread_count_; t++)
    {
        // initialise access thread data structures
        initPageAccessThreadData(dynArrayGet(&ws->access_threads_, t));
    }
    // split up resident files into worker thread units
    preparePageAccessThreadData(ws);



    // spin up worker threads
    for(size_t t = 0; t < ws->access_thread_count_; t++)
    {
        PageAccessThreadData *thread_data = dynArrayGet(&ws->access_threads_, t);

        // used to spin up worker threads on different CPUs
        pthread_attr_init(&thread_data->thread_attr_);

        CPU_ZERO(&cpu_mask);
        CPU_SET(used_cpus, &cpu_mask);
        pthread_attr_setaffinity_np(&thread_data->thread_attr_, sizeof(cpu_set_t), &cpu_mask);

        printf(WS_MGR_TAG "Thread %zu configured to run on core %d and to access %zu files.\n", t, used_cpus, thread_data->resident_files_.count_);
        thread_data->running_ = 1;
        if(pthread_create(&thread_data->tid_, &thread_data->thread_attr_, pageAccessThread, thread_data) != 0)
        {
            printf(FAIL WS_MGR_TAG "Error (%s) at creating access thread...\n", strerror(errno));
            goto error;
        }

        // increase to next core if wanted
        if((t+1) % ws->access_threads_per_core_ == 0)
        {
            // NOTE has to be locked when accessed concourrently in future
            used_cpus = (used_cpus + HYPERTHREADS_PER_CORE < MAX_CPUS) ? used_cpus + HYPERTHREADS_PER_CORE : used_cpus;
        }
    }


    while(__atomic_load_n(&running, __ATOMIC_RELAXED))
    {
        DEBUG_PRINT((DEBUG WS_MGR_TAG "WS manager thread running on core %d.\n", sched_getcpu()));

        // update ws profile
        if(runs_since_last_profile_update == ws->profile_update_all_x_evaluations_)
        {
            DEBUG_PRINT((DEBUG WS_MGR_TAG "Launching profile update - not implemented.\n"));
            // TODO
            // make new profile
            // split up into thread portions
            // spin up thread with new profile
            runs_since_last_profile_update = 0;
        }

        // reevaluate working set
        DEBUG_PRINT((DEBUG WS_MGR_TAG "Reevaluating working set...\n"));
        // reevaluateWorkingSet fails if eviction was run during the reevaluation
        if(ws->evaluation_ && reevaluateWorkingSet(ws) == 0)
        {
            DEBUG_PRINT((WS_MGR_TAG "Rescanned working set now consists of %zu files (%zu bytes mapped).\n", ws->tmp_resident_files_.count_, ws->tmp_mem_in_ws_));

            // acquire locks
            for(size_t t = 0; t < ws->access_thread_count_; t++)
            {
                PageAccessThreadData *thread_data = dynArrayGet(&ws->access_threads_, t);

                if(thread_data->running_)
                {
                    pthread_mutex_lock(&thread_data->resident_files_lock_);
                }
            }

            // swap lists 
            tmp_list_swap1 = ws->resident_files_;
            tmp_list_swap2 = ws->non_resident_files_;
            ws->resident_files_ = ws->tmp_resident_files_;
            ws->non_resident_files_ = ws->tmp_non_resident_files_;
            ws->tmp_resident_files_ = tmp_list_swap1;
            ws->tmp_non_resident_files_ = tmp_list_swap2;

            tmp_size_t = ws->mem_in_ws_;
            ws->mem_in_ws_ = ws->tmp_mem_in_ws_;
            ws->tmp_mem_in_ws_ = tmp_size_t;
        
            // rebalance files for threads
            preparePageAccessThreadData(ws);

            // release locks
            for(size_t t = 0; t < ws->access_thread_count_; t++)
            {
                PageAccessThreadData *thread_data = dynArrayGet(&ws->access_threads_, t);
        
                if(thread_data->running_)
                {
                    pthread_mutex_unlock(&thread_data->resident_files_lock_);
                }
            }
        }


        runs_since_last_profile_update++;
        nanosleep(&ws->evaluation_sleep_time_, NULL);
    }


    goto cleanup;

error:
    ret = (void *) -1;

cleanup:

    dynArrayDestroy(&ws->access_threads_, closePageAccessThreadData);

    return ret;
}


void preparePageAccessThreadData(AttackWorkingSet *ws)
{
    ListNode *current_head = NULL;
    size_t files_per_thread = 0;
    size_t processed_files = 0;
    size_t t = 0;


    if(ws->resident_files_.count_ == 0)
    {
        return;
    }


    // current head
    current_head = ws->resident_files_.head_;
    // pages per thread (rounded down)
    files_per_thread = ws->resident_files_.count_ / ws->access_thread_count_;
    // prepare thread_data objects
    for(t = 0; t < ws->access_thread_count_ - 1; t++)
    {
        PageAccessThreadData *thread_data = dynArrayGet(&ws->access_threads_, t);
        // prepare fake lists
        thread_data->sleep_time_ = ws->access_sleep_time_;
        thread_data->resident_files_.head_ = current_head;
        thread_data->resident_files_.count_ = files_per_thread;

        processed_files += files_per_thread;
        current_head = listGetIndex(&ws->resident_files_, processed_files);
    }

    PageAccessThreadData *thread_data = dynArrayGet(&ws->access_threads_, t);
    // prepare thread_data object for last thread
    thread_data->sleep_time_ = ws->access_sleep_time_;
    thread_data->resident_files_.head_ = current_head;
    thread_data->resident_files_.count_ = ws->resident_files_.count_ - processed_files;

    return;
}


int reevaluateWorkingSet(AttackWorkingSet *ws)
{
    // ensure the tmp variables are empty
    listDestroy(&ws->tmp_resident_files_, closeCachedFileArrayFreeOnly);
    listDestroy(&ws->tmp_non_resident_files_, closeCachedFileArrayFreeOnly);
    ws->tmp_mem_in_ws_ = 0;

    // reevaluate resident files list
    if(reevaluateWorkingSetList(&ws->resident_files_, ws) < 0)
    {
        return -1;
    }
    
    // reevaluate non resident files list
    if(reevaluateWorkingSetList(&ws->non_resident_files_, ws) < 0)
    {
        return -1;
    }
    
    return 0;
}


int reevaluateWorkingSetList(List *cached_file_list, AttackWorkingSet *ws) 
{
    ListNode *current_cached_file_node = NULL;
    ListNode *next_node = NULL;
    CachedFile current_cached_file = { 0 };
    
    // go cached files list
    current_cached_file_node = cached_file_list->head_;
    while(current_cached_file_node != NULL)
    {
        next_node = current_cached_file_node->next_;
        
        // copy current cached file and create a new dynarray
        current_cached_file = *((CachedFile *) current_cached_file_node->data_);
        if(!dynArrayInit(&current_cached_file.resident_page_sequences_, sizeof(PageSequence), ARRAY_INIT_CAP))
        {
           printf(FAIL "Error at dynArrayInit...\n"); 
           goto error;
        }
        
        // reevaluate file
        if(profileResidentPageSequences(&current_cached_file, ws->ps_add_threshold_) < 0)
        {
            printf(FAIL "Error at profileResidentPageSequences...\n");
            goto error;
        }
        
        // eviction is running stop 
        if(ws->eviction_ignore_evaluation_ && __atomic_load_n(&eviction_running, __ATOMIC_RELAXED) == 1)
        {
            printf(WARNING "Eviction occured during reevaluation, ignoring result...\n");
            goto error;
        }
        
        // move to file to tmp non resident file list
        if(current_cached_file.resident_memory_ == 0)
        {
            listAppendBack(&ws->tmp_non_resident_files_, &current_cached_file);
        }
        else 
        {
            listAppendBack(&ws->tmp_resident_files_, &current_cached_file);
            ws->tmp_mem_in_ws_ += current_cached_file.resident_memory_;
        }
        
        current_cached_file_node = next_node;
    }
    
    return 0;
    
error:
    
    dynArrayDestroy(&current_cached_file.resident_page_sequences_, NULL);
    
    return -1;
}


void *pageAccessThread(void* arg)
{
    PageAccessThreadData *page_thread_data = arg;
    volatile uint8_t tmp = 0;
    ListNode* resident_files_node = NULL;
    CachedFile *current_cached_file = NULL;
    PageSequence* resident_sequences = NULL;
    size_t resident_sequences_length = 0;
    size_t accessed_pages_count = 0;
    size_t accessed_files_count = 0;


    while(__atomic_load_n(&page_thread_data->running_, __ATOMIC_RELAXED))
    {
        DEBUG_PRINT((DEBUG WS_MGR_TAG "Worker thread (PSL: %p) running on core %d.\n", (void *) page_thread_data->resident_files_.head_, sched_getcpu()));
    
        pthread_mutex_lock(&page_thread_data->resident_files_lock_);
    
        accessed_files_count = 0;
        accessed_pages_count = 0;
        resident_files_node = page_thread_data->resident_files_.head_;
        while(resident_files_node != NULL && accessed_files_count < page_thread_data->resident_files_.count_)
        {
            current_cached_file = (CachedFile *) resident_files_node->data_;
            
            // advise random access to avoid readahead
            posix_fadvise(current_cached_file->fd_, 0, 0, POSIX_FADV_RANDOM);

            resident_sequences = current_cached_file->resident_page_sequences_.data_;
            resident_sequences_length = current_cached_file->resident_page_sequences_.size_;
    
            for(size_t s = 0; s < resident_sequences_length; s++)
            {
                for(size_t p = resident_sequences[s].offset_; p < resident_sequences[s].offset_ + resident_sequences[s].length_; p++)
                {
                    //printf("Accessing offset %zu, %zu length\n", resident_sequences[s].offset_, resident_sequences[s].length_);
                    //also works with NULL
                    pread(current_cached_file->fd_, (void *) &tmp, 1, p * PAGE_SIZE);
                    accessed_pages_count++;
                }      
            }
            
            accessed_files_count++;
            resident_files_node = resident_files_node->next_;
        }
        
        DEBUG_PRINT((DEBUG WS_MGR_TAG "Worker thread (PSL: %p) accessed %zu kB memory.\n", (void *) page_thread_data->resident_files_.head_, accessed_pages_count * PAGE_SIZE / 1024));
    
        pthread_mutex_unlock(&page_thread_data->resident_files_lock_);
    
    #ifdef USE_NANOSLEEP
        nanosleep(&page_thread_data->sleep_time_, NULL);
    #else
        sched_yield();
    #endif
    }

    return NULL;
}


size_t getMappingCount(const unsigned char* status, size_t size_in_pages)
{
    size_t mapped = 0;

    for(size_t p = 0; p < size_in_pages; p++)
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


void send(char *message, CovertChannel *covert_channel)
{
    static int even = 0;
    volatile uint8_t access = 0;
    unsigned char page_status = 0;
    char mask = 1;

    struct timespec time_start, time_end, wait_time;
    size_t elapsed_time_ms = 0;

    wait_time.tv_sec = 0;
    wait_time.tv_nsec = 1*1000*1000;

    // wait for ack
    DEBUG_PRINT((DEBUG "Sender: Wait for ack.\n"));
    do
    {
        nanosleep(&wait_time, NULL);
        mincore((uint8_t *) covert_channel->covert_file_mapping_.addr_ + ACK_PAGE_OFFSET*PAGE_SIZE, PAGE_SIZE, &page_status);
    }
    while(!(page_status & 1) && running);

    DEBUG_PRINT((DEBUG "Sender: Got ack.\n"));

    //updateRAMFillup(eviction_mem, fill_ram_child);

    clock_gettime(CLOCK_REALTIME, &time_start);
    evictMappedPages(covert_channel);
    clock_gettime(CLOCK_REALTIME, &time_end);

    elapsed_time_ms = (time_end.tv_sec - time_start.tv_sec) * 1000 +
                      (double) (time_end.tv_nsec - time_start.tv_nsec) / 1e6;
    DEBUG_PRINT((DEBUG"Eviction took approx. %zu ms.\n", elapsed_time_ms));

    // access pages
    clock_gettime(CLOCK_REALTIME, &time_start);
    for(size_t p = 0, b = 0; p < covert_channel->covert_file_mapping_.size_pages_ - CONTROL_PAGES; p++)
    {
        if(message[b] & mask)
        {
            access += *((uint8_t *) covert_channel->covert_file_mapping_.addr_ + p * PAGE_SIZE);
        }

        mask = mask << 1;
        if(!mask)
        {
            mask = 1;
            b++;
        }
    }
    clock_gettime(CLOCK_REALTIME, &time_end);

    elapsed_time_ms = (time_end.tv_sec - time_start.tv_sec) * 1000 +
                      (double) (time_end.tv_nsec - time_start.tv_nsec) / 1e6;
    DEBUG_PRINT((DEBUG"Accessing took %zums.\n", elapsed_time_ms));

    // send ready
    access += *((uint8_t *) covert_channel->covert_file_mapping_.addr_ + READY_PAGE_OFFSET[even]*PAGE_SIZE);
    even ^= 1;

    DEBUG_PRINT((DEBUG"Sender: Send message + ready.\n"));
}


void receive(char *message, CovertChannel *covert_channel)
{
    static int even = 0;
    volatile uint8_t access = 0;
    unsigned char ready_status = 0;
    char mask = 1;
    char byte = 0;
    struct timespec wait_time;

    wait_time.tv_sec = 0;
    wait_time.tv_nsec = 1*1000*1000;


    // wait for ready
    DEBUG_PRINT((DEBUG "Receiver: Wait for ready %d.\n", even + 1));
    do
    {
        nanosleep(&wait_time, NULL);
        mincore((uint8_t *) covert_channel->covert_file_mapping_.addr_ + READY_PAGE_OFFSET[even]*PAGE_SIZE, PAGE_SIZE, &ready_status);
    }
    while(!(ready_status & 1) && running);
    even ^= 1;
    DEBUG_PRINT((DEBUG "Receiver: Got ready %d.\n", even + 1));

    // receive information
    mincore(covert_channel->covert_file_mapping_.addr_, covert_channel->covert_file_mapping_.size_, covert_channel->covert_file_mapping_.page_status_);

    // get message
    for(size_t p = 0, b = 0; p < covert_channel->covert_file_mapping_.size_pages_ - CONTROL_PAGES; p++)
    {
        if(covert_channel->covert_file_mapping_.page_status_[p] & 1)
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


    // send ack
    access += *((uint8_t *) covert_channel->covert_file_mapping_.addr_ + ACK_PAGE_OFFSET*PAGE_SIZE);

    DEBUG_PRINT((DEBUG"Receiver: Send ack.\n"));
}


void usageError(char* app_name)
{
    printf(USAGE "%s [covert channel file] [-s|-r|-t]\n", app_name);
}
