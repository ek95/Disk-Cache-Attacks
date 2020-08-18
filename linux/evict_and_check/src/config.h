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
#define PU_INCREASE 1
#define DEF_USE_ATTACK_WS 1
#define DEF_USE_ATTACK_BS 1
#define DEF_MLOCK_SELF 1

#define ES_USE_THREADS
#define DEF_ES_ACCESS_THREAD_COUNT 6
#define DEF_ES_ACCESS_THREADS_PER_PU 2
// #define ES_USE_PREAD

#define DEF_WS_SEARCH_PATHS OBJ_SEARCH_PATHS
#define DEF_WS_PS_ADD_THRESHOLD READAHEAD_PAGES
#define DEF_WS_ACCESS_THREAD_COUNT 14
#define DEF_WS_ACCESS_THREADS_PER_PU 2
#define DEF_WS_ACCESS_SLEEP_TIME_NS 4000000UL
#define DEF_WS_ACCESS_SLEEP_TIME_S 0UL
#define DEF_WS_EVALUATION 1
#define DEF_WS_EVICTION_IGNORE_EVALUATION 1
#define DEF_WS_EVALUATION_SLEEP_TIME_NS 0UL
#define DEF_WS_EVALUATION_SLEEP_TIME_S 1UL
// TODO not implemented
#define DEF_WS_PROFILE_UPDATE_ALL_X_EVALUATIONS 60
// #define WS_MAP_FILE

// NOTE both for ES and WS
// #define PREAD_TWO_TIMES

// NOTE runtime of mincore can be neglected (<10ms)
#define DEF_MINCORE_CHECK_ALL_X_BYTES (DEF_PAGE_SIZE * 256UL)

#define DEF_BS_MEMINFO_FILE_PATH MEMINFO_PATH
// NOTE determines the granularity of the blocks added to the blocking set
#define DEF_BS_FILLUP_SIZE (16 * 1024 * 1024UL)
// NOTE uses /proc/meminfo as feedback source
// see also (https://github.com/torvalds/linux/blob/master/Documentation/filesystems/proc.rst)
#define DEF_BS_MIN_AVAILABLE_MEM (224 * 1024 * 1024UL) // 224
#define DEF_BS_MAX_AVAILABLE_MEM (288 * 1024 * 1024UL) // 288
#define DEF_BS_EVALUATION_SLEEP_TIME_NS 0UL
#define DEF_BS_EVALUATION_SLEEP_TIME_S 1UL

#define DEF_SS_THREAD_COUNT 0

// NOTE not relevant for eviction runtime
#define DEF_SAMPLE_WAIT_TIME_NS 10000UL
#define DEF_EVENT_WAIT_TIME_NS 50000000UL

#endif
