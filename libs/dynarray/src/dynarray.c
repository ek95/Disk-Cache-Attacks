#include "dynarray.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


void *dynArrayInit(DynArray *array, size_t elem_size, size_t init_cap)
{
    array->data_ = NULL;
    array->cap_ = 0;
    array->size_ = 0;
    array->elem_size_ = elem_size;
    
    // fast path
    if(init_cap == 0)
    {
        return NULL;
    }

    array->data_ = malloc(init_cap * array->elem_size_);
    if(array->data_ == NULL)
    {
        return NULL;
    }

    array->cap_ = init_cap;
    
    return array->data_;
}


void *dynArrayReserve(DynArray *array, size_t new_cap)
{
    void *tmp = NULL;

    if(array->cap_ > new_cap)
    {
        return array->data_;
    }

    tmp = realloc(array->data_, new_cap * array->elem_size_);
    if(tmp == NULL)
    {
        return NULL;
    }

    array->data_ = tmp;
    array->cap_ = new_cap;

    return array->data_;
}


void *dynArrayResize(DynArray *array, size_t new_size)
{
    if(dynArrayReserve(array, new_size) == NULL)
    {
        return NULL;
    }
    
    array->size_ = new_size;
    return array->data_;
}


void *dynArrayGet(DynArray *array, size_t index)
{
    if(index >= array->size_)
    {
        return NULL;
    }

    return (uint8_t *) array->data_ + index * array->elem_size_;
}


void *dynArraySet(DynArray *array, size_t index, void *data)
{
    void *dest = NULL;
    
    if(index >= array->size_)
    {
        return NULL;
    }

    dest = (uint8_t *) array->data_ + index * array->elem_size_;
    memcpy(dest, data, array->elem_size_);

    return dest;
}


void *dynArrayAppend(DynArray *array, void *data)
{
    void *tmp;
    void *dest;

    if(array->size_ == array->cap_)
    {
        tmp = realloc(array->data_, (array->cap_ + 1) * array->elem_size_ * 2);
        if(tmp == NULL)
        {
            return NULL;
        }
        array->data_ = tmp;
        array->cap_ = (array->cap_ + 1) * 2;
    }

    dest = (uint8_t *) array->data_ + array->size_ * array->elem_size_;
    memcpy(dest, data, array->elem_size_);
    array->size_++;
    
    return dest;
}


void dynArrayPop(DynArray *array, DynArrayDataCallbackArgFn callback, void *arg)
{
    if(array->size_ > 0 )
    {
        if(callback != NULL)
        {
            callback((uint8_t *) array->data_ + (array->size_ - 1) * array->elem_size_, arg);
        }
        
        array->size_--;
    }
}


void dynArrayReset(DynArray *array)
{
    array->size_ = 0;
}


void dynArrayDestroy(DynArray *array, DynArrayDataCallbackFn free_data)
{
    if(array->data_ != NULL)
    {
        if(free_data != NULL)
        {
            for(size_t offset = 0; offset < (array->size_ * array->elem_size_); offset += array->elem_size_)
            {
                free_data((uint8_t *) array->data_ + offset);
            }
        }
        
        free(array->data_);
        array->data_ = NULL;
    }
    
    array->size_ = 0;
    array->cap_ = 0;
}