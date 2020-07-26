#include <stdio.h>
#include "util/list/list.h"


#define TEST_START(x) printf("Running %d. test...\n", (x))
#define TEST_END(x) printf("%d. test completed successfully.\n", (x))


static int error = 0;
static int test_numbers[] = {1, 6, 3, 4, 10};
static int test_numbers2[] = {-1, 0, 11, 12};
static int test_numbers3[] = {1, 7, 6, 2, 3, 0, 4, 7, 10, 1};
static int test_numbers4[] = {2, 1, 7, 6, 1};
static int test_numbers5[] = {3, 0, 4, 7, 10};


int prepareList(List *list, int *values, size_t values_count)
{
   listInit(list, sizeof(int)); 
    
   for(size_t i = 0; i < values_count; i++) 
   {
       if(listAppendBack(list, &values[i]) == NULL) 
       {
           return -1;
       }
   }
   
   return 0;
}

int checkList(List *list, int *values, size_t values_count)
{
    ListNode *node = list->head_;
    size_t i = 0;
    
    while(node != NULL)
    {
        if(i == values_count) 
        {
            return -1;
        }
        
        int *current_value = (int *) node->data_;
        if(*current_value != values[i])
        {
            return -1;
        }
        
        node = node->next_;
        i++;
    }
    
    if(node != NULL || i != values_count)
    {
        return -1;
    }
    
    return 0;
}

int listCmpEqual(void *data, void *cmp_data)
{
    if(*((int *) data) == *((int *) cmp_data)) 
    {
        return 1;
    } 
    
    return 0;
}

int listCmpLessEqual(void* data, void* cmp_data)
{
    if(*((int *) data) <= *((int *) cmp_data))
    {
        return 1;
    }

    return 0;
}

void listForEachCB(void *data, void *arg) 
{
    static size_t i = 0;
    
    if(*((int *) data) != ((int *) arg)[i])
    {
        error = 1;
    }
    
    i++;
}

void listFreeDataCBTestNumbers3(void *data) 
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
    List numbers_list;
    List numbers_list2;
    List numbers_list3;
    ListNode *found_node;
    int number;
    
    
    // first test
    TEST_START(1);
    
    if(prepareList(&numbers_list, test_numbers, sizeof(test_numbers) / sizeof(int)) != 0)
        return -1;
        
    if(checkList(&numbers_list, test_numbers, sizeof(test_numbers) / sizeof(int)) != 0)
        return -1;
        
    if(*((int *) listGetIndex(&numbers_list, 0)->data_) != 1) 
        return -1;    
    if(*((int *) listGetIndex(&numbers_list, 2)->data_) != 3) 
        return -1;
    if(*((int *) listGetIndex(&numbers_list, 4)->data_) != 10) 
        return -1;
        
    listDestroy(&numbers_list, NULL);
    
    TEST_END(1);
  
  
    // second test
    TEST_START(2);
    
    listInit(&numbers_list, sizeof(int));
    listInit(&numbers_list2, sizeof(int));
    
    number = 0;
    if(listAppendFront(&numbers_list, &number) == NULL)
        return -1;
    number = -1;
    if(listAppendFront(&numbers_list, &number) == NULL)
        return -1;
        
    number = 11;
    if(listAppendBack(&numbers_list2, &number) == NULL)
        return -1;
    number = 12;
    if(listAppendBack(&numbers_list2, &number) == NULL)
        return -1;
        
    if(listChain(&numbers_list, &numbers_list2) == NULL)
        return -1;
        
    if(checkList(&numbers_list, test_numbers2, sizeof(test_numbers2) / sizeof(int)) != 0)
        return -1;
        
    listDestroy(&numbers_list, NULL);
    listDestroy(&numbers_list2, NULL);
    
    TEST_END(2);
    
    
    // third test
    TEST_START(3);
    
    if(prepareList(&numbers_list, test_numbers3, sizeof(test_numbers3) / sizeof(int)) != 0)
        return -1;
    
    listForEach(&numbers_list, listForEachCB, test_numbers3);
    if(error != 0)
        return -1;
    
    number = 1;
    found_node = listSearchFirst(&numbers_list, &number, listCmpEqual);
    if(found_node == NULL || found_node != listGetIndex(&numbers_list, 0))
        return -1;
    found_node = listSearchLast(&numbers_list, &number, listCmpEqual);
    if(found_node == NULL || found_node != listGetIndex(&numbers_list, 9))
        return -1;
        
    number = 7;
    found_node = listSearchFirst(&numbers_list, &number, listCmpEqual);
    if(found_node == NULL || found_node != listGetIndex(&numbers_list, 1))
        return -1;
    found_node = listSearchLast(&numbers_list, &number, listCmpEqual);
    if(found_node == NULL || found_node != listGetIndex(&numbers_list, 7))
        return -1;
    
    number = 0;
    found_node = listSearchFirst(&numbers_list, &number, listCmpLessEqual);
    if(found_node == NULL || *((int *) found_node->data_) != 0)
        return -1;
    found_node = listSearchLast(&numbers_list, &number, listCmpLessEqual);
    if(found_node == NULL || *((int *) found_node->data_) != 0)
        return -1;
    
    listDestroy(&numbers_list, NULL);
    
    TEST_END(3);
    
    
    // fourth test
    TEST_START(4);
    
    listInit(&numbers_list, sizeof(int));
    listInit(&numbers_list2, sizeof(int));
    listInit(&numbers_list3, sizeof(int));
    
    if(prepareList(&numbers_list2, test_numbers4, sizeof(test_numbers4) / sizeof(int)) != 0)
        return -1;
    if(prepareList(&numbers_list3, test_numbers5, sizeof(test_numbers5) / sizeof(int)) != 0)
        return -1;
        
    if(listChain(&numbers_list, &numbers_list2) == NULL)
        return -1;
    if(listChain(&numbers_list3, &numbers_list2) == NULL)
        return -1;
        
    if(listMoveNode(&numbers_list, listGetIndex(&numbers_list, 0), &numbers_list2) == NULL)
        return -1;
    if(listChain(&numbers_list2, &numbers_list3) == NULL)
        return -1;
    if(listMoveNode(&numbers_list, listGetIndex(&numbers_list, 3), &numbers_list2) == NULL)
        return -1;
    if(listChain(&numbers_list, &numbers_list2) == NULL)
        return -1;
        
    if(checkList(&numbers_list, test_numbers3, sizeof(test_numbers3) / sizeof(int)) != 0)
        return -1;
    
    listDestroy(&numbers_list, listFreeDataCBTestNumbers3);
    if(error != 0)
        return -1;
    listDestroy(&numbers_list2, NULL);
    listDestroy(&numbers_list3, NULL);

    TEST_END(4);
    
    
    return 0;
}