#ifndef _PCA_H_
#define _PCA_H_

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
#include "pageflags.h"
#endif


/*-----------------------------------------------------------------------------
 * DEFINES
 */
#define PCA_ARRAY_INIT_CAP 10
#define PCA_TARGETS_CONFIG_MAX_LINE_LENGTH 512
#define PCA_WINDOWS_BS_SEMAPHORE_NAME "Local\PCA_BS_CHILD"
#define PCA_WINDOWS_BS_COMMANDLINE "-b"
#define PCA_START_WIN_SPAWN_BS_CHILD 0x01
#define PCA_START_WIN_SPAWN_WS_CHILD 0x01


/*-----------------------------------------------------------------------------
 * TYPE DEFINITIONS
 */
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
    uint64_t has_target_pages_ : 1;
    uint64_t has_target_sequence_ : 1;
    uint64_t is_target_file_ : 1;
    uint64_t unused_: 61;
    FileMapping mapping_;
    union 
    {
        DynArray target_pages_;
        DynArray suppress_sequences_;
        PageSequence target_sequence_;
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
    char *meminfo_file_path_;
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
} AttackSuppressSet;

typedef struct _Attack_
{
    uint64_t use_attack_bs_ : 1;
    uint64_t use_attack_ws_ : 1;
    uint64_t use_attack_ss_ : 1;
    uint64_t mlock_self_ : 1;
    uint64_t unused_ : 59; // align to 8 byte

    AttackEvictionSet eviction_set_;
    AttackWorkingSet working_set_;
    pthread_t ws_manager_thread_;

    AttackBlockingSet blocking_set_;
    pthread_t bs_manager_thread_;

    HashMap targets_;

    size_t ra_window_size_pages_;
    AttackSuppressSet suppress_set_;
    size_t ss_thread_count_;
    DynArray ss_threads_;

    FileMapping event_obj_;
    pid_t event_child_;

    struct timespec sample_wait_time_;
    struct timespec event_wait_time_;
} Attack;


/*-----------------------------------------------------------------------------
 * PUBLIC FUNCTION PROTOTYPES
 */

int pcaInit(Attack *attack);
int pcaStart(Attack *attack, int flags);
TargetFile *pcaAddTargetFile(Attack *attack, char *target_file_path);
int pcaAddTargetsFromFile(Attack *attack, char *targets_config_file_path);
int pcaTargetPagesSampleFlushOnce(Attack *attack);
int pcaTargetFilesSampleFlushOnce(Attack *attack);
int pcaTargetFileRangeSampleFlushOnce(Attack *attack, TargetFile *target_file);
void pcaExit(Attack *attack);

#endif 