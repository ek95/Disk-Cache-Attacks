#include <stdio.h>
#include <assert.h>
#include "util/dynarray/dynarray.h"

#define ARRAY_INIT_CAP 100


static int error = 0;
static int test_numbers[] = {1, 6, 3, 4, 10};
static int test_numbers2[] = {1, 6, 5, 7, 8};
static int test_numbers3[] = {2, 6, 4, 7, 5};


int prepareDynArray(DynArray *array, int *values, size_t values_count)
{
   assert(dynArrayInit(array, sizeof(int), ARRAY_INIT_CAP) != NULL);
    
   for(size_t i = 0; i < values_count; i++) 
   {
       if(dynArrayAppend(array, &values[i]) == NULL) 
       {
           return -1;
       }
   }
   
   return 0;
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

void popCB(void *data, void *arg)
{
    if(*((int *) data) != (ssize_t) arg)
    {
        error = 1;
    }
}

void destroyTestNumbers3CB(void *data)
{
    static size_t i = 0;
    
    if(*((int *) data) != test_numbers3[i])
    {
        error = 1;
    }
    
    i++;
}


int main(int argc, char *argv[]) 
{
    DynArray numbers_array;
    int *raw_numbers_array = NULL;
    int number = 0;
    
    
    // first test
    assert(prepareDynArray(&numbers_array, test_numbers, sizeof(test_numbers) / sizeof(int)) == 0);
    assert(checkDynArray(&numbers_array, test_numbers, sizeof(test_numbers) / sizeof(int)) == 0);
    dynArrayDestroy(&numbers_array, NULL);
    
    
    // second test
    assert(dynArrayInit(&numbers_array, sizeof(int), 0) == NULL);
    assert(dynArrayResize(&numbers_array, sizeof(test_numbers2) / sizeof(int)) != NULL);
    raw_numbers_array = numbers_array.data_;
    for(size_t i = 0; i < sizeof(test_numbers2) / sizeof(int); i++)
    {
        raw_numbers_array[i] = test_numbers2[i];
    }
    
    for(ssize_t i =  sizeof(test_numbers2) / sizeof(int) - 1; i >= 0; i--)
    {
        dynArrayPop(&numbers_array, popCB, (void *) (ssize_t) test_numbers2[i]);
        assert(error == 0);
    }


    // third test
    dynArrayReset(&numbers_array);
    raw_numbers_array = numbers_array.data_;
    for(size_t i = 0; i < sizeof(test_numbers2) / sizeof(int); i++)
    {
        assert(dynArrayAppend(&numbers_array, &test_numbers2[i]) != NULL);
    }
    
    number = 2;
    assert(dynArraySet(&numbers_array, 0, &number) != NULL);
    number = 4;
    assert(dynArraySet(&numbers_array, 2, &number) != NULL);
    number = 5;
    assert(dynArraySet(&numbers_array, 4, &number) != NULL);

    for(ssize_t i =  sizeof(test_numbers3) / sizeof(int) - 1; i >= 0; i--)
    {
        dynArrayPop(&numbers_array, popCB, (void *) (ssize_t) test_numbers3[i]);
        assert(error == 0);
    }
    dynArrayDestroy(&numbers_array, NULL);


    // fourth test
    assert(prepareDynArray(&numbers_array, test_numbers3, sizeof(test_numbers3) / sizeof(int)) == 0);
    dynArrayDestroy(&numbers_array, destroyTestNumbers3CB);
    assert(error == 0);

    return 0;
}