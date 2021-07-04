#ifndef _CONFIG_H_
#define _CONFIG_H_

#include "filemap.h"

// General
#define DEF_USE_ATTACK_BS /*USE_ATTACK_BS*/
#define DEF_USE_ATTACK_WS /*USE_ATTACK_WS*/
#define DEF_USE_ATTACK_SS /*USE_ATTACK_SS*/

// mincore by default
#define DEF_FC_STATE_SOURCE FC FC_SOURCE_MINCORE
// readahead size (/sys/block/xxx/queue/read_ahead_kb)
#define DEF_FA_WINDOW_SIZE_PAGES 32

// Eviction Set
#define DEF_ES_USE_ANON_MEMORY /*USE_ANON_MEMORY*/
#define DEF_ES_USE_ACCESS_THREADS /*USE_ACCESS_THREADS*/
#define DEF_ES_USE_FILE_API /*USE_FILE_API*/
#define DEF_ES_EVICTION_FILE_PATH "eviction.ram"
#define DEF_TARGETS_CHECK_ALL_X_BYTES /*TARGETS_CHECK_ALL_X_BYTES*/
#define DEF_WS_ACCESS_ALL_X_BYTES /*WS_ACCESS_ALL_X_BYTES*/
#define DEF_SS_ACCESS_ALL_X_BYTES /*SS_ACCESS_ALL_X_BYTES*/
#define DEF_PREFETCH_ES_BYTES /*PREFETCH_ES_BYTES*/
#define DEF_ES_ACCESS_THREAD_COUNT /*ES_ACCESS_THREAD_COUNT*/

// Blocking Set
#define DEF_BS_FILLUP_SIZE (16 * 1024 * 4096ULL)
#define DEF_BS_MIN_AVAILABLE_MEM /*MIN_AVAILABLE_MEM*/
#define DEF_BS_MAX_AVAILABLE_MEM /*MAX_AVAILABLE_MEM*/
#define DEF_BS_EVALUATION_SLEEP_TIME_US /*BS_EVALUATION_SLEEP_TIME_US*/

// Working Set
#define DEF_WS_EVALUATION 1 
#define DEF_WS_EVICTION_IGNORE_EVALUATION 1  
#define DEF_WS_USE_FILE_API /*USE_FILE_API*/  
char* DEF_WS_SEARCH_PATHS[] =
{
    "/bin", "/dev/shm", "/etc", /*"/home",*/ "/lib", "/opt",
    "/run", "/sbin", "/snap", "/tmp", "/usr", "/var", NULL
};
#define DEF_WS_PS_ADD_THRESHOLD DEF_FA_WINDOW_SIZE_PAGES  
#define DEF_WS_ACCESS_SLEEP_TIME_US /*WS_ACCESS_SLEEP_TIME_US*/  
#define DEF_WS_EVALUATION_SLEEP_TIME_US /*WS_EVALUATION_SLEEP_TIME_US*/  
// not implemented yet
#define DEF_WS_PROFILE_UPDATE_ALL_X_EVALUATIONS (0)    
#define DEF_WS_ACCESS_THREAD_COUNT /*WS_ACCESS_THREAD_COUNT*/  

// Suppress Set
#define DEF_SS_USE_FILE_API /*SS_USE_FILE_API */  
#define DEF_SS_ACCESS_SLEEP_TIME_US /*SS_ACCESS_SLEEP_TIME_US*/  
#define DEF_SS_ACCESS_THREAD_COUNT /*SS_ACCESS_THREAD_COUNT */

#endif
