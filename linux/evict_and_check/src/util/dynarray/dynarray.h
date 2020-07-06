#ifndef _DYN_ARRAY_H_
#define _DYN_ARRAY_H_

#include <stddef.h>


typedef struct _DynArray_
{
    void *data_;
    size_t size_;
    size_t cap_;
    size_t elem_size_;
} DynArray;

typedef void (*DynArrayDataCallbackArgFn)(void *addr, void *arg);
typedef void (*DynArrayDataCallbackFn)(void *addr);

void *dynArrayInit(DynArray *array, size_t elem_size, size_t init_cap);
void *dynArrayReserve(DynArray *array, size_t new_cap);
void *dynArrayResize(DynArray *array, size_t new_size);
void *dynArrayAppend(DynArray *array, void *data);
void *dynArraySet(DynArray *array, size_t index, void *data);
void dynArrayPop(DynArray *array, DynArrayDataCallbackArgFn callback, void *arg);
void dynArrayDestroy(DynArray *array, DynArrayDataCallbackFn free_data);
void *dynArrayGet(DynArray *array, size_t index);
void dynArrayReset(DynArray *array);

#endif
