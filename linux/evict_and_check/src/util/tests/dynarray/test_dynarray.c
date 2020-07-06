#include <stdio.h>
#include <assert.h>
#include "util/dynarray/dynarray.h"

#define ARRAY_INIT_CAP 100


static int error = 0;
static int test_numbers[] = {1, 6, 3, 4, 10};
static int test_numbers2[] = {1, 6, 5, 7, 8};


void prepareDynArray(DynArray *array, int *values, size_t values_count)
{
   assert(dynArrayInit(array, sizeof(int), ARRAY_INIT_CAP) != NULL);
    
   for(size_t i = 0; i < values_count; i++) 
   {
       assert(dynArrayAppend(array, &values[i]) != NULL);
   }
}

int checkDynArray(DynArray *array, int *values, size_t values_count)
{
    if(array->size_ != values_count) 
    {
        return -1;
    }
    
    for(size_t i = 0; i < array->size_; i++) 
    {
        if(values[i] != *((int *) dynArrayGet(array, i)))
        {
            return -1;
        }
    }
    
    return 0;
}

void pop_cb(void *data, void *arg)
{
    if(*((int *) data) != (ssize_t) arg)
    {
        error = 1;
    }
}

void destroy_cb(void *data)
{
    static size_t i = 0;
    
    if(*((int *) data) != test_numbers2[i])
    {
        error = 1;
    }
    
    i++;
}


int main(int argc, char *argv[]) 
{
    DynArray numbers_array;
    int *raw_numbers_array = NULL;
    
    
    // first test
    prepareDynArray(&numbers_array, test_numbers, sizeof(test_numbers) / sizeof(int));
    assert(checkDynArray(&numbers_array, test_numbers, sizeof(test_numbers) / sizeof(int)) == 0);
    dynArrayDestroy(&numbers_array, NULL);
    
    
    // second test
    assert(dynArrayInit(&numbers_array, sizeof(int), 0) == NULL);
    assert(dynArrayReserve(&numbers_array, sizeof(test_numbers2) / sizeof(int)) != NULL);
    raw_numbers_array = numbers_array.data_;
    for(size_t i = 0; i < sizeof(test_numbers2) / sizeof(int); i++)
    {
        raw_numbers_array[i] = test_numbers2[i];
    }
    
    for(ssize_t i =  sizeof(test_numbers2) / sizeof(int) - 1; i >= 0; i--)
    {
        dynArrayPop(&numbers_array, pop_cb, (void *) (ssize_t) test_numbers2[i]);
        assert(error == 0);
    }


    // third test
    dynArrayReset(&numbers_array);
    raw_numbers_array = numbers_array.data_;
    for(size_t i = 0; i < sizeof(test_numbers2) / sizeof(int); i++)
    {
        dynArrayAppend(&numbers_array, &test_numbers2[i]);
    }
    
    for(ssize_t i =  sizeof(test_numbers2) / sizeof(int) - 1; i >= 0; i--)
    {
        dynArrayPop(&numbers_array, pop_cb, (void *) (ssize_t) test_numbers2[i]);
        assert(error == 0);
    }

    dynArrayDestroy(&numbers_array, destroy_cb);
    assert(error == 0);

    return 0;
}