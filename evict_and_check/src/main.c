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

/*-----------------------------------------------------------------------------
 * INCLUDES
 */
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#ifdef __linux
#include <signal.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#elif defined(_WIN32)
#include "windows.h"
#endif
#include "cmdline.h"
#include "filemap.h"
#include "config.h"
#include "fca.h"
#include "osal.h"


/*-----------------------------------------------------------------------------
 * DEFINES
 */

// defines used for parsing command line arguments
#define SWITCHES_COUNT 2
#define EXT_EVENT_APP_SWITCH 0
#define FCA_WINDOWS_BS_SWITCH 1
const char *SWITCHES_STR[SWITCHES_COUNT] = {"-e", "-b"};
const size_t SWITCHES_ARG_COUNT[SWITCHES_COUNT] = {1, 1};
#define MANDATORY_ARGS 1
#define TARGETS_CONFIG_PATH_ARG 0
#define USAGE_MSG "Usage: %s [targets configuration file] <-e executable> \n\n"                             \
                  "\t[target configuration file]\n"                                                         \
                  "\t\tConfiguration file which contains the shared file-page pairs to which accesses\n"    \
                  "\t\tshould be monitored.\n\n"                                                            \
                  "\t-e executable (optional)\n"                                                            \
                  "\t\tAllows to specify an executable which is signaled in case of\n"                      \
                  "\t\tan detected event (SIGUSR1).\n\n"                                       

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
static void configAttackFromDefines(Attack *attack);
static void printSampleTrace(Attack *attack);
int targetsHmPrintSampleTraceCB(void *data, void *arg);
static void usageError(char *app_name);

/*-----------------------------------------------------------------------------
 * GLOBAL VARIABLES
 */
static int running = 1;

/*-----------------------------------------------------------------------------
 * SIGNAL HANDLERS
 */
static void quitHandler(int signal)
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
    int ret = 0;
#ifdef __linux
    struct sigaction quit_act = {0};
#elif defined (_WIN32)
    // TODO
#endif

    // variables used for processing command line arguments
    CmdLineConf cmd_line_conf =
    {
        .mandatory_args_count_ = MANDATORY_ARGS,
        .switches_count_ = SWITCHES_COUNT,
        .switches_ = SWITCHES_STR,
        .switches_arg_count_ = SWITCHES_ARG_COUNT
    };
    CmdLineParsed parsed_cmd_line;

    // variables necessary for general attack function
    Attack attack = {0};
    FileMapping self_mapping = {0};
    FileMapping event_exec_mapping = {0};
    pid_t event_child = 0;
    size_t hit_counter = 0;
    size_t sum_eviction_accessed_memory = 0;
    size_t sum_eviction_time_ns = 0;

    // initialise file mappings
    initFileMapping(&self_mapping);
    initFileMapping(&event_exec_mapping);
    // initialise random generator
    srand(time(NULL));

    // set output buffering to lines (needed for automated testing)
    setvbuf(stdout, NULL, _IOLBF, 0);

    // process command line arguments
    if (parseCmdArgs(&argv[1], argc - 1, &cmd_line_conf, &parsed_cmd_line) != 0)
    {
        usageError(argv[0]);
        goto error;
    }

    // register signal handler for quiting the program by SRTG+C
#ifdef __linux
    quit_act.sa_handler = quitHandler;
    ret = sigaction(SIGINT, &quit_act, NULL);
    ret += sigaction(SIGQUIT, &quit_act, NULL);
    ret += sigaction(SIGUSR1, &quit_act, NULL);
    if (ret != 0)
    {
        printf(FAIL "Error " OSAL_EC_FS " at sigaction...\n", OSAL_EC);
        goto error;
    }
#elif defined(_WIN32)
    // TODO
#endif

    // initialising attack
    if (fcaInit(&attack) != 0)
    {
        printf(FAIL "Error " OSAL_EC_FS " at fcaInit...\n", OSAL_EC);
        goto error;
    }

    // optional: mlock self
#ifdef MLOCK_SELF
    // map self
    if (mapFile(&self_mapping, argv[0], 
        FILE_ACCESS_READ | FILE_NOATIME, MAPPING_SHARED | MAPPING_ACCESS_READ) != 0)
    {
        printf(FAIL "Error " OSAL_EC_FS " at mapFile for: %s...\n", OSAL_EC, argv[0]);
        goto error;
    }

    // TODO windows virtual lock
    // mlock self
    ret = mlock(self_mapping.addr_, self_mapping.size_);
    if (ret != 0)
    {
        printf(WARNING "Error " OSAL_EC_FS " mlock for: %s...\n", OSAL_EC, argv[0]);
    }
#endif

    // optional: map and mlock event binary
    if (parsed_cmd_line.switch_args_[EXT_EVENT_APP_SWITCH][0] != NULL)
    {
        // map event binary
        if (mapFile(&event_exec_mapping, parsed_cmd_line.switch_args_[EXT_EVENT_APP_SWITCH][0],
            FILE_ACCESS_READ | FILE_NOATIME, MAPPING_SHARED | MAPPING_ACCESS_READ) != 0)
        {
            printf(FAIL "Error " OSAL_EC_FS " at mapFile for: %s...\n", OSAL_EC, parsed_cmd_line.switch_args_[EXT_EVENT_APP_SWITCH][0]);
            goto error;
        }

        ret = mlock(event_exec_mapping.addr_, event_exec_mapping.size_);
        if (ret != 0)
        {
            printf(FAIL "Error " OSAL_EC_FS " at mlock for: %s...\n", OSAL_EC, parsed_cmd_line.switch_args_[EXT_EVENT_APP_SWITCH][0]);
        }

        // TODO Windows create process
        event_child = fork();
        if (event_child < 0)
        {
            printf(FAIL "Error " OSAL_EC_FS " at fork...\n", OSAL_EC);
            goto error;
        }
        else if (event_child == 0)
        {
            char *event_argv[] = {NULL};
            execv(parsed_cmd_line.switch_args_[EXT_EVENT_APP_SWITCH][0], event_argv);
            printf(FAIL "Error " OSAL_EC_FS " at execv for: %s...\n", OSAL_EC, parsed_cmd_line.switch_args_[EXT_EVENT_APP_SWITCH][0]);
            goto error;
        }
    }

    // sample configuration
    configAttackFromDefines(&attack);

    // add targets from configuration file
    if(fcaAddTargetsFromFile(&attack, parsed_cmd_line.mandatory_args_[TARGETS_CONFIG_PATH_ARG]) != 0)
    {
        printf(FAIL "Error " OSAL_EC_FS " at fcaAddTargetsFromFile...\n", OSAL_EC);
        goto error;   
    }

    // start fca attack
    if(fcaStart(&attack, 0) != 0)
    {
        printf(FAIL "Error " OSAL_EC_FS " at fcaStart...\n", OSAL_EC);
        goto error;
    }

    printf(OK "Ready...\n");
    // main event loop
    while (running)
    {
        // sample
        ret = fcaTargetsSampleFlushOnce(&attack);
        if(ret < 0)
        {
            printf(FAIL "Error " OSAL_EC_FS " at fcaTargetPagesSampleFlushOnce...\n", OSAL_EC);
            goto error;  
        }

        // process results if a hit occured
        if(ret == 1)
        {
            sum_eviction_time_ns += attack.eviction_set_.last_eviction_time_ns_;
            sum_eviction_accessed_memory += attack.eviction_set_.last_eviction_accessed_memory_bytes_;
            hit_counter++;

            printf(INFO "Hit %zu (eviction time: %zu ns, accessed eviction set: %zu kB)\n", 
                hit_counter, attack.eviction_set_.last_eviction_time_ns_, 
                attack.eviction_set_.last_eviction_accessed_memory_bytes_ / 1024);
            // print page trace
            printSampleTrace(&attack);
        }

        osal_sched_yield();
    }

    if (hit_counter > 0)
    {
        printf(INFO "Mean time to eviction per hit: %f ns..\n", (double)sum_eviction_time_ns / hit_counter);
        printf(INFO "Mean accessed eviction set per hit: %f kB..\n", (double)sum_eviction_accessed_memory / 1024 / hit_counter);
    }

    goto cleanup;

error:
    ret = -1;

cleanup:

    fcaExit(&attack);
#ifdef MLOCK_SELF
    closeFileMapping(&self_mapping);
#endif
    freeCmdLineParsed(&cmd_line_conf, &parsed_cmd_line);

    return ret;
}

void configAttackFromDefines(Attack *attack)
{
    // General
    attack->use_attack_bs_ = DEF_USE_ATTACK_BS;
    attack->use_attack_ws_ = DEF_USE_ATTACK_WS;
    attack->use_attack_ss_ = DEF_USE_ATTACK_SS;
    
    attack->fc_state_source_ = DEF_FC_STATE_SOURCE;
    attack->fa_window_size_pages_ = DEF_FA_WINDOW_SIZE_PAGES;

    // Eviction Set
    attack->eviction_set_.use_anon_memory_ = DEF_ES_USE_ANON_MEMORY;
    attack->eviction_set_.use_access_threads_ = DEF_ES_USE_ACCESS_THREADS;
    attack->eviction_set_.use_file_api_ = DEF_ES_USE_FILE_API;
    attack->eviction_set_.eviction_file_path_ = DEF_ES_EVICTION_FILE_PATH;
    attack->eviction_set_.targets_check_all_x_bytes_ = DEF_TARGETS_CHECK_ALL_X_BYTES;
    attack->eviction_set_.ws_access_all_x_bytes_ = DEF_WS_ACCESS_ALL_X_BYTES;
    attack->eviction_set_.ss_access_all_x_bytes_ = DEF_SS_ACCESS_ALL_X_BYTES;
    attack->eviction_set_.prefetch_es_bytes_ = DEF_PREFETCH_ES_BYTES;
    // only if .use_access_threads_ is set
    attack->eviction_set_.access_thread_count_ = DEF_ES_ACCESS_THREAD_COUNT;

    // Blocking Set
    attack->blocking_set_.def_fillup_size_ = DEF_BS_FILLUP_SIZE;
    attack->blocking_set_.min_available_mem_ = DEF_BS_MIN_AVAILABLE_MEM;
    attack->blocking_set_.max_available_mem_ = DEF_BS_MAX_AVAILABLE_MEM;
    attack->blocking_set_.evaluation_sleep_time_.tv_sec = DEF_BS_EVALUATION_SLEEP_TIME_S;
    attack->blocking_set_.evaluation_sleep_time_.tv_nsec = DEF_BS_EVALUATION_SLEEP_TIME_NS;

    // Working Set
    attack->working_set_.evaluation_ = DEF_WS_EVALUATION;
    attack->working_set_.eviction_ignore_evaluation_ = DEF_WS_EVICTION_IGNORE_EVALUATION;
    attack->working_set_.use_file_api_ = DEF_WS_USE_FILE_API;
    attack->working_set_.search_paths_ = DEF_WS_SEARCH_PATHS;
    attack->working_set_.ps_add_threshold_ = DEF_WS_PS_ADD_THRESHOLD;
    attack->working_set_.access_sleep_time_.tv_sec = DEF_WS_ACCESS_SLEEP_TIME_S;
    attack->working_set_.access_sleep_time_.tv_nsec = DEF_WS_ACCESS_SLEEP_TIME_NS;
    attack->working_set_.evaluation_sleep_time_.tv_sec = DEF_WS_EVALUATION_SLEEP_TIME_S;
    attack->working_set_.evaluation_sleep_time_.tv_nsec = DEF_WS_EVALUATION_SLEEP_TIME_NS;
    attack->working_set_.profile_update_all_x_evaluations_ = DEF_WS_PROFILE_UPDATE_ALL_X_EVALUATIONS;
    attack->working_set_.access_thread_count_ = DEF_WS_ACCESS_THREAD_COUNT;

    // Suppress Set
    attack->suppress_set_.use_file_api_ = DEF_SS_USE_FILE_API;
    attack->suppress_set_.access_sleep_time_.tv_sec = DEF_SS_ACCESS_SLEEP_TIME_S;
    attack->suppress_set_.access_sleep_time_.tv_nsec = DEF_SS_ACCESS_SLEEP_TIME_NS;
    attack->suppress_set_.access_thread_count_ = DEF_SS_ACCESS_THREAD_COUNT;
}

void printSampleTrace(Attack *attack) 
{
    hashMapForEach(&attack->targets_, targetsHmPrintSampleTraceCB, NULL);
}

int targetsHmPrintSampleTraceCB(void *data, void *arg) 
{
    TargetFile *target_file = data;
    TargetPage *target_pages = target_file->target_pages_.data_;
    (void) arg;

    for (size_t i = 0; i < target_file->target_pages_.size_; i++)
    {   
        // print when a hit was detected
        if(target_file->last_sample_fc_status_[target_pages[i].offset_])
        {
            printf("%zu;%s;%zu\n", target_pages[i].last_sample_time_, target_file->file_path_abs_, target_pages[i].offset_);
        }
    }

    return HM_FE_OK;
}

void usageError(char *app_name)
{
    printf(USAGE USAGE_MSG, app_name);
}
