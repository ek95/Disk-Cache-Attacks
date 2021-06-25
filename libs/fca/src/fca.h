#ifndef _FCA_H_
#define _FCA_H_

#define _GNU_SOURCE
#define _DEFAULT_SOURCE

/*-----------------------------------------------------------------------------
 * INCLUDES
 */
#include <stdint.h>
#include "dynarray.h"
#include "list.h"
#include "hashmap.h"
#include "filemap.h"
#include "osal.h"
#ifdef __linux
#include <pthread.h>
#endif


/*-----------------------------------------------------------------------------
 * DEFINES
 */
#define FCA_ARRAY_INIT_CAP 10
#define FCA_IN_LINE_MAX 1024
#define FCA_LINUX_MEMINFO_PATH "/proc/meminfo"
#define FCA_LINUX_MEMINFO_AVAILABLE_MEM_TAG "MemAvailable:"
#define FCA_WINDOWS_BS_SEMAPHORE_NAME "Local\FCA_BS_CHILD"
#define FCA_WINDOWS_BS_COMMANDLINE "-b"
#define FCA_START_WIN_SPAWN_BS_CHILD 0x01
#define FCA_START_WIN_SPAWN_WS_CHILD 0x01

#define FCA_TARGET_TYPE_FILE 0x00
#define FCA_TARGET_TYPE_PAGES 0x01
#define FCA_TARGET_TYPE_PAGE_SEQUENCE 0x02
#define FCA_TARGET_TYPE_PAGE_SEQUENCES 0x03

/*-----------------------------------------------------------------------------
 * TYPE DEFINITIONS
 */
// forward declaration
typedef struct _Attack_ Attack;

typedef int (*TargetsEvictedFn)(void *arg);

typedef struct _TargetPage_ 
{
    uint64_t no_eviction_ : 1;
    uint64_t unused_: 63;
    size_t offset_;
} TargetPage;

typedef struct _PageSequence_
{
    size_t offset_;
    size_t length_;
} PageSequence;

typedef struct _TargetFile_ 
{
    union 
    {
        struct 
        {
            uint64_t has_target_pages_ : 1;
            uint64_t has_target_sequence_ : 1;
            uint64_t has_target_sequences_ : 1;
            uint64_t is_target_file_ : 1;
            uint64_t unused_: 61;
        };
        uint64_t flags_;
    };
    FileMapping mapping_;
    union 
    {
        DynArray target_pages_;
        PageSequence target_sequence_;
        DynArray target_sequences_;
    };
} TargetFile;

typedef struct _FillUpProcess_
{
    osal_pid_t pid_;
    size_t fillup_size_;
} FillUpProcess;

typedef struct _CachedFile_
{
    FileMapping mapping_;
    size_t resident_memory_;
    DynArray resident_page_sequences_;
    TargetFile *linked_target_file_;
} CachedFile;

typedef struct _AttackEvictionSet_
{
    uint64_t use_anon_memory_ : 1;
    uint64_t use_access_threads_: 1;
    uint64_t use_file_api_: 1;
    uint64_t unused_ : 61; // align to 8bytes
    char *eviction_file_path_;
    char *eviction_file_path_abs_;
    FileMapping mapping_;
    size_t initialise_samples_;
    size_t initialise_max_runs_;  
    size_t targets_check_all_x_bytes_;
    size_t ws_access_all_x_bytes_;
    size_t ss_access_all_x_bytes_;
    size_t prefetch_es_bytes_;
    // only used if ES_USE_THREADS is defined
    size_t access_thread_count_;
    size_t access_threads_per_pu_;
    DynArray access_threads_;
    sem_t worker_start_sem_;
    sem_t worker_join_sem_;
} AttackEvictionSet;

typedef struct _PageAccessThreadESData_
{
    pthread_t tid_;
    int running_;
    Attack *attack_;
    size_t access_offset_;
    size_t access_len_;
    size_t accessed_mem_;
    TargetsEvictedFn targets_evicted_fn_; 
    void *targets_evicted_arg_ptr_;
    sem_t *start_sem_;
    sem_t *join_sem_;
} PageAccessThreadESData;

typedef struct _AttackBlockingSet_
{
    pthread_t manager_thread_;
    DynArray fillup_processes_;
    size_t def_fillup_size_;
    size_t min_available_mem_;
    size_t max_available_mem_;
    struct timespec evaluation_sleep_time_;
    sem_t initialized_sem_;
    uint8_t initialized_;
} AttackBlockingSet;

typedef struct _AttackWorkingSet_
{
    uint64_t evaluation_ : 1;
    uint64_t eviction_ignore_evaluation_ : 1;
    uint64_t access_use_file_api_ : 1;
    uint64_t unused_ : 61; // align to 8bytes

    pthread_t manager_thread_;
    char **search_paths_;
    size_t checked_files_;
    size_t memory_checked_;
    // two sets of lists, protected by a read-write lock
    size_t up_to_date_list_set_;
    List resident_files_[2];
    List non_resident_files_[2];
    size_t mem_in_ws_[2];
    pthread_rwlock_t ws_lists_lock_;
   
    size_t ps_add_threshold_;
    struct timespec access_sleep_time_;
    struct timespec evaluation_sleep_time_;
    size_t profile_update_all_x_evaluations_;

    // TODO for windows processes are/should be used
    size_t access_thread_count_;
    DynArray access_threads_;

} AttackWorkingSet;

typedef struct _PageAccessThreadWSData_
{
    pthread_t tid_;
    int id_;
    int running_;
    AttackWorkingSet *ws_;
    struct timespec sleep_time_;
} PageAccessThreadWSData;

typedef struct _AttackSuppressSet_
{
    uint64_t use_file_api_: 1;
    uint64_t unused_ : 63; // align to 8bytes
    DynArray suppress_set_;
    struct timespec access_sleep_time_;
    size_t access_thread_count_;
    DynArray access_threads_;
} AttackSuppressSet;

typedef struct _PageAccessThreadSSData_
{
    pthread_t tid_;
    int running_;
    AttackSuppressSet *ss_;
    struct timespec sleep_time_;
} PageAccessThreadSSData;

typedef struct _Attack_
{
    uint64_t use_attack_bs_ : 1;
    uint64_t use_attack_ws_ : 1;
    uint64_t use_attack_ss_ : 1;
    uint64_t mlock_self_ : 1;
    uint64_t unused_ : 59; // align to 8 byte

    int fc_state_source_;

    AttackEvictionSet eviction_set_;
    AttackBlockingSet blocking_set_;
    AttackWorkingSet working_set_;

    HashMap targets_;

    size_t ra_window_size_pages_;
    AttackSuppressSet suppress_set_;
} Attack;


/*-----------------------------------------------------------------------------
 * PUBLIC FUNCTION PROTOTYPES
 */

/* Initialise file cache attack structure.
 * After this call you have to set the configuration fields in attack and
 * use fcaAddTarget...() to add the target files.
 * Call this before running any other fca...() function.
 *
 * @param[in]   attack  pointer to the attack structure
 * @return      -1 on error, 0 otherwise
 * 
 */ 
int fcaInit(Attack *attack);

/* Adds a target file by its path, the TargetFile structure is returned
 * and can be used to customize the TargetFile configuration further.
 * You need to do this before fcaStart() so that the target files can 
 * be accounted when profiling the working set for example.
 *
 * @param[in]   attack  pointer to the attack structure
 * @param[in]   target_file_path  path to the target file
 * @return      NULL on error, valid pointer otherwise
 * 
 */ 
TargetFile *fcaAddTargetFile(Attack *attack, char *target_file_path);

/* Adds a target files using a configuration file. 
 * The allowed structure for the configuration file can be seen
 * in the examples provided in /.
 *
 * @param[in]   attack                    pointer to the attack structure
 * @param[in]   targets_config_file_path  path to the targets configuration file
 * @return      -1 on error, 0 otherwise
 * 
 */ 
int fcaAddTargetsFromFile(Attack *attack, char *targets_config_file_path);

/* Starts the attack.
 * Prepares everything according to the set configuration and the given
 * targets. 
 * Spawns all necessary worker threads.
 * After this call you can use fcaTarget...SampleFlushOnce() to sample the targets.
 *
 * @param[in]   attack  pointer to the attack structure
 * @param[in]   flags   optional flags for the startup routine, neccesary for Windows
 * @return      -1 on error, 0 otherwise
 * 
 */ 
int fcaStart(Attack *attack, int flags);

/* Target state sample function.
 * Selection depends on the type of target you use.

 * In case of target pages use this function.
 * 
 * The results of the sampling can be found by iterating over the
 * attack.targets_ hashmap in the mapping_.pages_cache_status_ vector.
 *
 * @param[in]   attack  pointer to the attack structure
 * @return      -1 on error, 0 otherwise
 * 
 */ 
int fcaTargetPagesSampleFlushOnce(Attack *attack);

/* Target state sample function.
 * Selection depends on the type of target you use.

 * In case of (whole) target files use this function.
 * 
 * The results of the sampling can be found by iterating over the
 * attack.targets_ hashmap in the mapping_.pages_cache_status_ vector.
 *
 * @param[in]   attack  pointer to the attack structure
 * @return      -1 on error, 0 otherwise
 * 
 */ 
int fcaTargetFilesSampleFlushOnce(Attack *attack);

/* Target state sample function.
 * Selection depends on the type of target you use.

 * In case of a target page sequence use this function.

 * The target page sequence can be changed by modifying the TargetFile
 * object. Note however that this does not affect the already created
 * working and suppression set. Therefore, increasing the page sequence
 * afterwards will lead to problems. Using a smaller sequence is allowed,
 * but still does not update the working and suppression set 
 * (which could even be wanted in this case).
 * 
 * The results of the sampling can be found by iterating over the
 * attack.targets_ hashmap in the mapping_.pages_cache_status_ vector.
 *
 * @param[in]   attack  pointer to the attack structure
 * @return      -1 on error, 0 otherwise
 * 
 */ 
int fcaTargetFilePageSequence(Attack *attack, TargetFile *target_file);

/* Stops the attack.
 * Exits every thread, frees all resources and hands back control.
 * 
 */ 
void fcaExit(Attack *attack);

#endif 