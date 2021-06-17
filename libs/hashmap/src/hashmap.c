#include "hashmap.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "list.h"


int hashMapInit(HashMap *map, size_t elem_size, size_t buckets) 
{
    // allocate entries
    map->map_ = malloc(buckets * sizeof(List));
    if(map->map_ == NULL) 
    {
        return -1;
    }

    // initialise entry lists
    for(size_t b = 0; b < buckets; b++) 
    {
        listInit(&map->map_[b], sizeof(HashMapEntry));
    }

    map->elem_size_ = elem_size;
    map->buckets_ = buckets;

    return 0;
}


// very simple
static size_t hashFunction(HashMap *map, uint8_t *data, size_t size) 
{
    size_t rep = 0;
    // might overflow - do not care
    for(size_t i = 0; i < size; i++) {
        rep += data[i];
    }
    // reduce
    return rep % map->buckets_;
}


static int hashFindEntryOverflowListCmp(void *data, void *cmp_data)
{
    HashMapEntry *candidate = data;
    HashMapEntry *to_find = cmp_data;

    // can not be the same
    if(candidate->key_size_ != to_find->key_size_) 
    {
        return 0;
    }

    return memcmp(candidate->key_, to_find->key_, to_find->key_size_) == 0 ? 1 : 0;
}


static HashMapEntry *bucketGetEntry(List *bucket, void *key, size_t key_size) 
{
    // fast path
    if(bucket->count_ == 0) 
    {
        return NULL;
    }
    // slow path
    else 
    {
        HashMapEntry to_find = {
            .key_ = key,
            .key_size_ =  key_size
        };
        ListNode *node = listSearchFirst(bucket, &to_find, hashFindEntryOverflowListCmp);
        if(node == NULL)
        {
            return NULL;
        }
        else 
        {
            return node->data_;
        }
    }
}


void *hashMapGet(HashMap *map, void *key, size_t key_size) 
{
    List *bucket = &map->map_[hashFunction(map, key, key_size)];
    HashMapEntry *entry = bucketGetEntry(bucket, key, key_size);
    return entry == NULL ? NULL : entry->data_;
}


static int freeHashMapEntry(void *arg)
{
    HashMapEntry *entry = arg;
    free(entry->key_);
    free(entry->data_);
    return 0;
}


void *hashMapInsert(HashMap *map, void *key, size_t key_size, void *data)
{
    // allocate data
    void *key_dup = malloc(key_size * sizeof(uint8_t));
    if(key_dup == NULL) 
    {
        return NULL;
    }
    void *data_dup = malloc(map->elem_size_);
    if(data_dup == NULL) 
    {
        free(key_dup);
        return NULL;
    }

    // copy data
    memcpy(key_dup, key, key_size);
    memcpy(data_dup, data, map->elem_size_);

    // insert into bucket
    List *bucket = &map->map_[hashFunction(map, key, key_size)];
    HashMapEntry new_entry = 
    {
        .key_ = key_dup,
        .key_size_ = key_size,
        .data_ = data_dup 
    };

    // is already in bucket?
    HashMapEntry *old_entry = bucketGetEntry(bucket, key, key_size);
    if(old_entry != NULL) 
    {
        freeHashMapEntry(old_entry);
        *old_entry = new_entry;
        return data_dup;
    }
    // no -> new entry
    else 
    {
        if(listAppendBack(bucket, &new_entry) == NULL) 
        {   
            freeHashMapEntry(&new_entry);
            return NULL;
        }
        else 
        {
            return data_dup;
        }
    }
}


static int hashMapForEachCallback(void *data, void *arg)
{
    struct _ForEachArg_ *for_each_arg = arg;
    HashMapEntry *entry = data;
    return for_each_arg->callback_(entry->data_, for_each_arg->arg_);
}


int hashMapForEach(HashMap *map, HashMapDataCallbackArgFn callback, void *arg) 
{
    int ret = 0;
    struct _ForEachArg_ for_each_arg = 
    {
        .callback_ = callback,
        .arg_ = arg
    };

    // apply function for every element in hash list
    for(size_t b = 0; b < map->buckets_; b++) 
    {
        ret = listForEach(&map->map_[b], hashMapForEachCallback, &for_each_arg);
        if(ret == LIST_FE_BREAK) 
        {
            return HM_FE_BREAK;
        }
    }

    return HM_FE_OK;
}


void hashMapDestroy(HashMap *map, HashMapDataCallbackFn free_data) 
{
    if(map->map_ == NULL) 
    {
        return;
    }

    for(size_t s = 0; s < map->buckets_; s++) 
    {
        if(free_data != NULL)
        {
            listForEachSimple(&map->map_[s], free_data);
        }
        listDestroy(&map->map_[s], freeHashMapEntry);
    }
    free(map->map_);
    map->map_ = NULL;
    map->buckets_ = 0;
    map->elem_size_ = 0;
}