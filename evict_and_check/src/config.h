#ifndef _CONFIG_H_
#define _CONFIG_H_

// General
#define DEF_USE_ATTACK_BS 0
#define DEF_USE_ATTACK_WS 1
#define DEF_USE_ATTACK_SS 0

// mincore by default
#define DEF_FC_STATE_SOURCE 0x100
// readahead size (/sys/block/xxx/queue/read_ahead_kb)
#define DEF_FA_WINDOW_SIZE_PAGES 32

// Eviction Set
#define DEF_ES_USE_ANON_MEMORY 0
#define DEF_ES_USE_ACCESS_THREADS 0
#define DEF_ES_USE_FILE_API 0
#define DEF_ES_EVICTION_FILE_PATH "eviction.ram"
// allow it to be max. 1ms
#define DEF_TARGETS_CHECK_ALL_X_BYTES (64 * 4096ULL)
// at least once inbetween eviction set filled file LRU lists
// (heuristic: min available memory / 2)
#define DEF_WS_ACCESS_ALL_X_BYTES (32 * 1024 * 4096ULL) //(125829 * 4096ULL)//(125829 * 4096ULL)
// more often
// (heuristic: min available memory / 4)
#define DEF_SS_ACCESS_ALL_X_BYTES (8000 * 4096ULL)
// depends on hard disk
#define DEF_PREFETCH_ES_BYTES (1024 * 4096ULL)
#define DEF_ES_ACCESS_THREAD_COUNT 6

// Blocking Set
#define DEF_BS_FILLUP_SIZE (8 * 1024 * 4096ULL)
// good guess might be made by looking at the watermarks in /proc/zoneinfo
// 6% - 8%
#define DEF_BS_MIN_AVAILABLE_MEM (128 * 1024 * 1024ULL)//(251658 * 4096ULL)
#define DEF_BS_MAX_AVAILABLE_MEM (DEF_BS_MIN_AVAILABLE_MEM + 2 * DEF_BS_FILLUP_SIZE)//(335545 * 4096ULL)
#define DEF_BS_EVALUATION_SLEEP_TIME_US (500)

// Working Set
#define DEF_WS_EVALUATION 0
#define DEF_WS_EVICTION_IGNORE_EVALUATION 1  
#define DEF_WS_USE_FILE_API 1
char* DEF_WS_SEARCH_PATHS[] =
{
    "/home/erik/test"
#ifdef NOOOOOOOOOOOOO
    /*"/bin",*/ "/boot", "/etc", "/home", /*"/lib",*/ "/opt",
    "/run", /*"/sbin",*/ "/srv", "/snap", "/tmp", "/usr", "/var", NULL
#endif
};
#define DEF_WS_PS_ADD_THRESHOLD (1)
#define DEF_WS_ACCESS_SLEEP_TIME_US (15000) 
#define DEF_WS_EVALUATION_SLEEP_TIME_US (10000ULL)  
// not implemented yet
#define DEF_WS_PROFILE_UPDATE_ALL_X_EVALUATIONS 0 
#define DEF_WS_ACCESS_THREAD_COUNT 6

// Suppress Set
#define DEF_SS_USE_FILE_API 0 
#define DEF_SS_ACCESS_SLEEP_TIME_US (10 * 1000ULL)  
#define DEF_SS_ACCESS_THREAD_COUNT 4

#endif
