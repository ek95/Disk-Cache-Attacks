#ifndef _HASHMAP_H_
#define _HASHMAP_H_

#include <stddef.h>
#include "list.h"


typedef ListDataCallbackFn HashMapCallbackFn;
typedef ListDataCallbackArgFn HashMapCallbackArgFn ;

struct _ForEachArg_ 
{
    HashMapCallbackArgFn callback_;
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
void hashMapForEach(HashMap *map, HashMapCallbackArgFn callback, void *arg);
void hashMapDestroy(HashMap *map, HashMapCallbackFn free_data);

#endif
