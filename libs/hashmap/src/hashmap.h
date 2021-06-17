#ifndef _HASHMAP_H_
#define _HASHMAP_H_

#include <stddef.h>
#include "list.h"


#define HM_FE_OK LIST_FE_OK
#define HM_FE_BREAK LIST_FE_BREAK


typedef ListDataCallbackFn HashMapDataCallbackFn;
typedef ListDataCallbackArgFn HashMapDataCallbackArgFn;


struct _ForEachArg_ 
{
    HashMapDataCallbackArgFn callback_;
    void *arg_;
};

typedef struct _HashMapEntry_
{
    void *key_;
    size_t key_size_;
    void *data_;
} HashMapEntry;

typedef struct _HashMap_ 
{
    List *map_;
    size_t elem_size_;
    size_t buckets_;
} HashMap;


int hashMapInit(HashMap *map, size_t elem_size, size_t buckets);
void *hashMapGet(HashMap *map, void *key, size_t key_size);
void *hashMapInsert(HashMap *map, void *key, size_t key_size, void *data);
int hashMapForEach(HashMap *map, HashMapDataCallbackArgFn callback, void *arg);
void hashMapDestroy(HashMap *map, HashMapDataCallbackFn free_data);

#endif
