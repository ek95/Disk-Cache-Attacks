#ifndef _PCA_H_
#define _PCA_H_

/*-----------------------------------------------------------------------------
 * INCLUDES
 */
#include <stdint.h>
#include "dynarray.h"
#include "list.h"
#include "hashmap.h"
#include "filemap.h"
#include "osal.h"
#ifdef _linux
#include "pageflags.h"
#endif


/*-----------------------------------------------------------------------------
 * DEFINES
 */
#define PCA_ARRAY_INIT_CAP 10
#define PCA_TARGETS_CONFIG_MAX_LINE_LENGTH 512

/*-----------------------------------------------------------------------------
 * TYPE DEFINITIONS
 */
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
    FileMapping mapping_;
    union 
    {
        DynArray target_pages_;
        PageSequence target_sequence_;
    };
} TargetFile;

typedef struct _CachedFile_
{
    FileMapping mapping_;
    size_t resident_memory_;
    DynArray resident_page_sequences_;
} CachedFile;

typedef struct _FillUpProcess_
{
    osal_pid_t pid_;
    size_t fillup_size_;
} FillUpProcess;

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
    size_t page_offset_;
    size_t size_pages_;
    sem_t *start_sem_;
    sem_t *join_sem_;
    size_t accessed_mem_;
} PageAccessThreadESData;

typedef struct _AttackWorkingSet_
{
    uint64_t evaluation_ : 1;
    uint64_t eviction_ignore_evaluation_ : 1;
    uint64_t unused_ : 62; // align to 8bytes

    char **search_paths_;
    size_t checked_files_;
    size_t memory_checked_;
    size_t mem_in_ws_;
    size_t tmp_mem_in_ws_;
    List resident_files_;
    List non_resident_files_;
    List tmp_resident_files_;
    List tmp_non_resident_files_;
    size_t ps_add_threshold_;
    size_t access_thread_count_;
    size_t access_threads_per_pu_;
    DynArray access_threads_;
    struct timespec access_sleep_time_;
    struct timespec evaluation_sleep_time_;
    size_t profile_update_all_x_evaluations_;
} AttackWorkingSet;

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

typedef struct _AttackSuppressSet_
{
    DynArray target_readahead_window_;
    struct timespec access_sleep_time_;
} AttackSuppressSet;

typedef struct _PageAccessThreadWSData_
{
    pthread_mutex_t resident_files_lock_;
    List resident_files_;
    struct timespec sleep_time_;
    int running_;
    pthread_t tid_;
    pthread_attr_t thread_attr_;
} PageAccessThreadWSData;

typedef struct _Attack_
{
    uint64_t use_attack_ws_ : 1;
    uint64_t use_attack_bs_ : 1;
    uint64_t mlock_self_ : 1;
    uint64_t sampling_mode_: 1;
    uint64_t unused_ : 60; // align to 8 byte

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

typedef int (*TargetsEvictedFn)(void *arg);



/*-----------------------------------------------------------------------------
 * FUNCTION PROTOTYPES
 */
// helper functions for custom datatypes
void initCachedFile(CachedFile *cached_file);
void closeCachedFile(void *arg);
void closeCachedFileArrayFreeOnly(void *arg);
void initFillUpProcess(FillUpProcess *fp);
void closeFillUpProcess(void *arg);
void closeThread(void *arg);
int initAttackEvictionSet(AttackEvictionSet *es);
void closeAttackEvictionSet(AttackEvictionSet *es);
int initAttackWorkingSet(AttackWorkingSet *ws);
void closeAttackWorkingSet(AttackWorkingSet *ws);
int initAttackBlockingSet(AttackBlockingSet *bs);
void closeAttackBlockingSet(AttackBlockingSet *bs);
int initAttackSuppressSet(AttackSuppressSet *ss);
void closeAttackSuppressSet(AttackSuppressSet *ss);
void initPageAccessThreadESData(PageAccessThreadESData *ps_access_thread_es_data);
void closePageAccessThreadESData(void *arg);
void initPageAccessThreadWSData(PageAccessThreadWSData *ps_access_thread_ws_data);
void closePageAccessThreadWSData(void *arg);
int initAttack(Attack *attack);
void exitAttack(Attack *attack);

#endif 