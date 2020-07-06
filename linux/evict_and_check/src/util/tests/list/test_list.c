#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include "util/list/list.h"

#define RANDOM_TEST_NODE_COUNT 10000
#define RANDOM_TEST_NODE_MAX_VALUE 100000

int error = 0;
int test_numbers[] = {1, 6, 3, 4, 10};
int test_numbers2[] = {1, 6, 3, 4, 10, 11};
int test_numbers3[] = {1, 6, 2, 3, 4, 10};
int test_numbers4[] = {1, 6};
int test_numbers5[] = {3, 6, 5, 7, 2 , 6};


void prepareList(List *list, int *values, size_t values_count)
{
   listInit(list, sizeof(int)); 
    
   for(size_t i = 0; i < values_count; i++) 
   {
       assert(listAppendBack(list, &values[i]) != NULL);
   }
}

int checkList(List *list, int *values, size_t values_count)
{
    ListNode *node = list->head_;
    size_t i = 0;
    
    while(node != NULL)
    {
        int *current_value = (int *) node->data_;
        
        if(i == values_count) 
        {
            break;
        }
        
        if(*current_value != values[i])
        {
            return -1;
        }
        
        i++;
        node = node->next_;
    }
    
    if(node != NULL || i != values_count)
    {
        return -1;
    }
    
    return 0;
}

int list_cmp1(void *node, void *value)
{
    if(*((int *) node) == *((int *) value)) 
    {
        return 1;
    } 
    
    return 0;
}

int list_cmp2(void* node, void* value)
{
    if(*((int *)value) > *((int *)node))
    {
        return 1;
    }

    return 0;
}

void for_each_cb(void *data, void *arg) 
{
    static size_t i = 0;
    
    if(*((int *) data) != ((int *) arg)[i])
    {
        error = 1;
    }
    
    i++;
}

void free_data_cb(void *data) 
{
    static size_t i = 0;
    
    if(*((int *) data) != test_numbers5[i])
    {
        error = 1;
    }
    
    i++;
}


int main(int argc, char *argv[]) 
{
    List numbers_list;
    int number;
    
    srand(time(NULL));
    
    // first test
    prepareList(&numbers_list, test_numbers, sizeof(test_numbers) / sizeof(int));
    assert(checkList(&numbers_list, test_numbers, sizeof(test_numbers) / sizeof(int)) == 0);
    assert(*((int *) listGetIndex(&numbers_list, 2)->data_) == 3);
    listDestroy(&numbers_list, NULL);
  
    // second test
    number = 11;
    prepareList(&numbers_list, test_numbers, sizeof(test_numbers) / sizeof(int));
    assert(listAppendBack(&numbers_list, &number) != NULL);
    assert(checkList(&numbers_list, test_numbers2, sizeof(test_numbers2) / sizeof(int)) == 0);
    assert(*((int *) listGetIndex(&numbers_list, 2)->data_) == 3);
    listDestroy(&numbers_list, NULL);
  
    // third  test
    listInit(&numbers_list, sizeof(int));
    number = 1;
    assert(listAppendBack(&numbers_list, &number) != NULL);
    number = 6;
    assert(listAppendBack(&numbers_list, &number) != NULL);
    assert(checkList(&numbers_list, test_numbers4, sizeof(test_numbers4) / sizeof(int)) == 0);
    listDestroy(&numbers_list, NULL);
    
    // fourth test
    listInit(&numbers_list, sizeof(int));
    prepareList(&numbers_list, test_numbers5, sizeof(test_numbers5) / sizeof(int));
    listForEach(&numbers_list, for_each_cb, test_numbers5);
    assert(error == 0);
    listDestroy(&numbers_list, free_data_cb);
    assert(error == 0);
    
    return 0;
}