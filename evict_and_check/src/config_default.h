#ifndef _CONFIG_H_
#define _CONFIG_H_

#include "filemap.h"

// General
#define DEF_USE_ATTACK_BS 1
#define DEF_USE_ATTACK_WS 0
#define DEF_USE_ATTACK_SS 0

// mincore by default
#define DEF_FC_STATE_SOURCE FC_SOURCE_MINCORE
// useful for attacks which depend on multiple pages
#define DEF_RESAMPLE_SLEEP_TIME_US 0
// readahead size (/sys/block/xxx/queue/read_ahead_kb)
#define DEF_FA_WINDOW_SIZE_PAGES 32

// Eviction Set
#define DEF_ES_USE_ANON_MEMORY 0
#define DEF_ES_USE_ACCESS_THREADS 0
#define DEF_ES_USE_FILE_API 0
#define DEF_ES_EVICTION_FILE_PATH "eviction.ram"
#define DEF_ES_TARGETS_CHECK_ALL_X_BYTES (1024 * 4096ULL)
#define DEF_ES_WS_ACCESS_ALL_X_BYTES (0)
#define DEF_ES_SS_ACCESS_ALL_X_BYTES (0)
#define DEF_ES_PREFETCH_ES_BYTES (1024 * 4096ULL)
#define DEF_ES_ACCESS_THREAD_COUNT 6

// Blocking Set
#define DEF_BS_FILLUP_SIZE (8 * 1024 * 4096ULL)
#define DEF_BS_MIN_AVAILABLE_MEM (32 * 1024 * 4096ULL)
#define DEF_BS_MAX_AVAILABLE_MEM (DEF_BS_MIN_AVAILABLE_MEM + 2 * DEF_BS_FILLUP_SIZE)
#define DEF_BS_EVALUATION_SLEEP_TIME_US (10 * 1000ULL)

// Working Set
#define DEF_WS_EVALUATION 1
#define DEF_WS_EVICTION_IGNORE_EVALUATION 1  
#define DEF_WS_USE_FILE_API 1 
char* DEF_WS_SEARCH_PATHS[] =
{
    "/bin", "/dev/shm", "/etc", /*"/home",*/ "/lib", "/opt",
    "/run", "/sbin", "/snap", "/tmp", "/usr", "/var", NULL
};
#define DEF_WS_PS_ADD_THRESHOLD 1
#define DEF_WS_ACCESS_SLEEP_TIME_US (15 * 1000ULL)
#define DEF_WS_EVALUATION_SLEEP_TIME_US (30 * 1000 * 1000ULL)
// not implemented yet
#define DEF_WS_PROFILE_UPDATE_ALL_X_EVALUATIONS (0)    
#define DEF_WS_ACCESS_THREAD_COUNT 6

// Suppress Set
#define DEF_SS_USE_FILE_API 1 
#define DEF_SS_ACCESS_SLEEP_TIME_US (1000ULL)
#define DEF_SS_ACCESS_THREAD_COUNT 6

#endif
