#ifndef _CONFIG_H_
#define _CONFIG_H_


// defines regarding the attacked system
//------------------------------------------------------------------------------
// default page size if could not be determined
#define DEF_PAGE_SIZE 4096
// readahead size (/sys/block/xxx/queue/read_ahead_kb)
#define READAHEAD_PAGES 32
// file paths, tags
#define MEMINFO_PATH "/proc/meminfo" // NOTE default update resolution is 1s
#define MEMINFO_AVAILABLE_MEM_TAG "MemAvailable:"
#define RANDOM_SOURCE_PATH "/dev/urandom"
char* OBJ_SEARCH_PATHS[] =
{
    "/bin", "/dev/shm", "/etc", /*"/home",*/ "/lib", "/opt",
    "/run", "/sbin", "/snap", "/tmp", "/usr", "/var", NULL
};
// ram hit threshold
#define RAM_HIT_THRESHOLD 1000


// defines for tuning the attack
//------------------------------------------------------------------------------
#define USE_NANOSLEEP
#define PU_INCREASE /*PU_INCREASE*/
#define DEF_USE_ATTACK_WS /*USE_ATTACK_WS*/
#define DEF_USE_ATTACK_BS /*USE_ATTACK_BS*/
#define DEF_MLOCK_SELF 1

#define DEF_WS_SEARCH_PATHS OBJ_SEARCH_PATHS
#define DEF_WS_PS_ADD_THRESHOLD /*WS_PS_ADD_THRESHOLD*/
#define DEF_WS_ACCESS_THREAD_COUNT /*WS_ACCESS_THREAD_COUNT*/
#define DEF_WS_ACCESS_THREADS_PER_PU /*WS_ACCESS_THREADS_PER_PU*/
#define DEF_WS_ACCESS_SLEEP_TIME_NS /*WS_ACCESS_SLEEP_TIME_NS*/
#define DEF_WS_ACCESS_SLEEP_TIME_S /*WS_ACCESS_SLEEP_TIME_S*/
#define DEF_WS_EVALUATION /*WS_EVALUATION*/
#define DEF_WS_EVICTION_IGNORE_EVALUATION /*WS_EVICTION_IGNORE_EVALUATION*/
#define DEF_WS_EVALUATION_SLEEP_TIME_NS /*WS_EVALUATION_SLEEP_TIME_NS*/
#define DEF_WS_EVALUATION_SLEEP_TIME_S /*WS_EVALUATION_SLEEP_TIME_S*/
// TODO not implemented
#define DEF_WS_PROFILE_UPDATE_ALL_X_EVALUATIONS 60

// NOTE runtime of mincore can be neglected (<10ms)
#define DEF_MINCORE_CHECK_ALL_X_BYTES (DEF_PAGE_SIZE * 256UL)

#define DEF_BS_MEMINFO_FILE_PATH MEMINFO_PATH
// NOTE determines the granularity of the blocks added to the blocking set
#define DEF_BS_FILLUP_SIZE /*BS_FILLUP_SIZE*/
// NOTE uses /proc/meminfo as feedback source
// see also (https://github.com/torvalds/linux/blob/master/Documentation/filesystems/proc.rst)
#define DEF_BS_MIN_AVAILABLE_MEM /*BS_MIN_AVAILABLE_MEM*/
#define DEF_BS_MAX_AVAILABLE_MEM /*BS_MAX_AVAILABLE_MEM*/
#define DEF_BS_EVALUATION_SLEEP_TIME_NS /*BS_EVALUATION_SLEEP_TIME_NS*/
#define DEF_BS_EVALUATION_SLEEP_TIME_S /*BS_EVALUATION_SLEEP_TIME_S*/

#define DEF_SS_THREAD_COUNT 0

// NOTE not relevant for eviction runtime
#define DEF_SAMPLE_WAIT_TIME_NS 10000UL
#define DEF_EVENT_WAIT_TIME_NS 50000000UL


#endif
