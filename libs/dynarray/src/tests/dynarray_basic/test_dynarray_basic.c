#include <stdio.h>
#include "dynarray.h"


#define ARRAY_INIT_CAP 100


#define TEST_START(x) printf("Running %d. test...\n", (x))
#define TEST_END(x) printf("%d. test completed successfully.\n", (x))


static int error = 0;
static int test_numbers[] = {1, 6, 3, 4, 10};
static int test_numbers2[] = {1, 6, 5, 7, 8};
static int test_numbers3[] = {2, 6, 4, 7, 5};


int prepareDynArray(DynArray *array, int *values, size_t values_count)
{
   if(dynArrayInit(array, sizeof(int), ARRAY_INIT_CAP) == NULL)
   {
       return -1;
   }

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

int popCB(void *data, void *arg)
{
    if(*((int *) data) != (ssize_t) arg)
    {
        error = 1;
    }
    return 0;
}

int destroyTestNumbers3CB(void *data)
{
    static size_t i = 0;

    if(*((int *) data) != test_numbers3[i])
    {
        error = 1;
    }

    i++;
    return 0;
}


int main(int argc, char *argv[])
{
    DynArray numbers_array = {0};
    int *raw_numbers_array = NULL;
    int number = 0;


    // first test
    TEST_START(1);

    if(prepareDynArray(&numbers_array, test_numbers, sizeof(test_numbers) / sizeof(int)) != 0)
        return -1;
    if(checkDynArray(&numbers_array, test_numbers, sizeof(test_numbers) / sizeof(int)) != 0)
        return -1;
    dynArrayDestroy(&numbers_array, NULL);

    TEST_END(1);


    // second test
    TEST_START(2);

    if(dynArrayInit(&numbers_array, sizeof(int), 0) != NULL)
        return -1;
    if(dynArrayResize(&numbers_array, sizeof(test_numbers2) / sizeof(int)) == NULL)
        return -1;
    raw_numbers_array = numbers_array.data_;
    for(size_t i = 0; i < sizeof(test_numbers2) / sizeof(int); i++)
    {
        raw_numbers_array[i] = test_numbers2[i];
    }

    for(ssize_t i =  sizeof(test_numbers2) / sizeof(int) - 1; i >= 0; i--)
    {
        dynArrayPop(&numbers_array, popCB, (void *) (ssize_t) test_numbers2[i]);
        if(error != 0)
            return -1;
    }

    TEST_END(2);


    // third test
    TEST_START(3);

    dynArrayReset(&numbers_array);
    raw_numbers_array = numbers_array.data_;
    for(size_t i = 0; i < sizeof(test_numbers2) / sizeof(int); i++)
    {
        if(dynArrayAppend(&numbers_array, &test_numbers2[i]) == NULL)
            return -1;
    }

    number = 2;
    if(dynArraySet(&numbers_array, 0, &number) == NULL)
        return -1;
    number = 4;
    if(dynArraySet(&numbers_array, 2, &number) == NULL)
        return -1;
    number = 5;
    if(dynArraySet(&numbers_array, 4, &number) == NULL)
        return -1;

    for(ssize_t i =  sizeof(test_numbers3) / sizeof(int) - 1; i >= 0; i--)
    {
        dynArrayPop(&numbers_array, popCB, (void *) (ssize_t) test_numbers3[i]);
        if(error != 0)
            return -1;
    }
    dynArrayDestroy(&numbers_array, NULL);

    TEST_END(3);


    // fourth test
    TEST_START(4);

    if(prepareDynArray(&numbers_array, test_numbers3, sizeof(test_numbers3) / sizeof(int)) != 0)
        return -1;
    dynArrayDestroy(&numbers_array, destroyTestNumbers3CB);
    if(error != 0)
        return -1;

    TEST_END(4);


    return 0;
}
