#ifndef _CONFIG_H_
#define _CONFIG_H_


// defines regarding the attacked system
//------------------------------------------------------------------------------
// default page size if could not be determined
#define DEF_PAGE_SIZE 4096
// readahead size (/sys/block/xxx/queue/read_ahead_kb)
#define READAHEAD_PAGES 32
// file paths, tags
#define EVICTION_FILENAME "eviction.ram"
#define MEMINFO_PATH "/proc/meminfo" // NOTE default update resolution is 1s
#define MEMINFO_AVAILABLE_MEM_TAG "MemAvailable:"
#define NULL_PATH "/dev/null"
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
// little benefitial effect for covert channel + might introduce transmission 
// errors
#define DEF_USE_ATTACK_WS 0
#define DEF_USE_ATTACK_BS 1
#define DEF_MLOCK_SELF 1

#define ES_USE_THREADS
#define DEF_ES_ACCESS_THREAD_COUNT 10
#define DEF_ES_ACCESS_THREADS_PER_PU 1
//#define ES_USE_PREAD

#define DEF_WS_SEARCH_PATHS OBJ_SEARCH_PATHS
#define DEF_WS_PS_ADD_THRESHOLD (READAHEAD_PAGES)
#define DEF_WS_ACCESS_THREAD_COUNT 3
#define DEF_WS_ACCESS_THREADS_PER_PU 1
#define DEF_WS_ACCESS_SLEEP_TIME_NS 5000000L
#define DEF_WS_ACCESS_SLEEP_TIME_S 0UL
#define DEF_WS_EVALUATION 1
#define DEF_WS_EVICTION_IGNORE_EVALUATION 1
#define DEF_WS_EVALUATION_SLEEP_TIME_NS 0UL
#define DEF_WS_EVALUATION_SLEEP_TIME_S 1UL
// TODO not implemented
#define DEF_WS_PROFILE_UPDATE_ALL_X_EVALUATIONS 60
//#define WS_MAP_FILE

// NOTE both for ES and WS
#define PREAD_TWO_TIMES

// NOTE runtime of mincore can be neglected
#define DEF_MINCORE_CHECK_ALL_X_BYTES (32 * DEF_PAGE_SIZE * 256UL)
// NOTE runtime of mincore can be neglected
#define DEF_WS_MINCORE_CHECK_SLEEP_TIME_S 0UL
#define DEF_WS_MINCORE_CHECK_SLEEP_TIME_NS 500000UL
#define DEF_WS_FLAG_CHECK_SLEEP_TIME_S 0UL
#define DEF_WS_FLAG_CHECK_SLEEP_TIME_NS 1000000UL

#define DEF_BS_MEMINFO_FILE_PATH MEMINFO_PATH
// NOTE determines the granularity of the blocks added to the blocking set
#define DEF_BS_FILLUP_SIZE (16 * 1024 * 1024UL)
// NOTE uses /proc/meminfo as feedback source
// see also (https://github.com/torvalds/linux/blob/master/Documentation/filesystems/proc.rst)
// adapted for covert channel
#define DEF_BS_MIN_AVAILABLE_MEM (224 * 1024 * 1024UL)
#define DEF_BS_MAX_AVAILABLE_MEM (288 * 1024 * 1024UL)
#define DEF_BS_EVALUATION_SLEEP_TIME_NS 0UL
#define DEF_BS_EVALUATION_SLEEP_TIME_S 1UL

// covert channel defines
#define MESSAGE_SIZE (8 * 1024UL) // in byte
#define CONTROL_PAGES 3UL
#define COVERT_FILE_SIZE ((MESSAGE_SIZE * 8 + CONTROL_PAGES) * PAGE_SIZE)
#define ACK_PAGE_OFFSET (MESSAGE_SIZE * 8)
const size_t READY_PAGE_OFFSET[2] = {MESSAGE_SIZE * 8 + 1, MESSAGE_SIZE * 8 + 2};

#endif