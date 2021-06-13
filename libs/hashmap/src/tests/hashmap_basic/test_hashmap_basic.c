#include <stdio.h>
#include <string.h>
#include "hashmap.h"


#define TEST_START(x) printf("Running %d. test...\n", (x))
#define TEST_END(x) printf("%d. test completed successfully.\n", (x))


// contains element that go into the same bucket
// (hash function very simple)
static char* TEST_KEYS[] = { "element1", "element2", "element3",  "elemenv1", "elemenu2", NULL };
static size_t TEST_DATA[] = { 1, 2, 3, 31, 32 };

static size_t sum = 0;


void sumEntries(void *data, void *arg) 
{
    (void) arg;
    size_t *num = data;

    sum += *num;
}


int main(int argc, char *argv[])
{
    HashMap hash_map;
    size_t *val_ptr = NULL;
    size_t new_val = 0;


    // first test
    // tests init + insert + get
    TEST_START(1);
    if(hashMapInit(&hash_map, sizeof(size_t), 997) != 0) 
    {
        return -1;
    }
    
    // insert all test values 
    for(size_t i = 0; TEST_KEYS[i] != NULL; i++) 
    {
        if(hashMapInsert(&hash_map, TEST_KEYS[i], strlen(TEST_KEYS[i]), &TEST_DATA[i]) == NULL) 
        {
            return -1;
        }
    }

    // check if values are stored right
    for(size_t i = 0; TEST_KEYS[i] != NULL; i++) 
    {
        val_ptr = hashMapGet(&hash_map, TEST_KEYS[i], strlen(TEST_KEYS[i]));
        if(val_ptr == NULL || *val_ptr != TEST_DATA[i]) 
        {
            return -1;
        }
    }
    TEST_END(1);


    // second test
    // tests overwriting existing values
    TEST_START(2);
    new_val = 111;
    if(hashMapInsert(&hash_map, TEST_KEYS[0], strlen(TEST_KEYS[0]), &new_val) == NULL) 
    {
        return -1;
    }

    val_ptr = hashMapGet(&hash_map, TEST_KEYS[0], strlen(TEST_KEYS[0]));
    if(val_ptr == NULL || *val_ptr != new_val) 
    {
        return -1;
    }
    TEST_END(2);


    // third test
    // tests for each
    TEST_START(3);
    size_t sum_should = new_val;
    for(size_t i = 1; TEST_KEYS[i] != NULL; i++) 
    {
        sum_should += TEST_DATA[i];
    }
    hashMapForEach(&hash_map, sumEntries , NULL);
    if(sum != sum_should) 
    {
        return -1;
    }
    TEST_END(3);


    // fourth test
    // corners + destroy
    TEST_START(4);
    // trying to get a non-existing element
    char *non_existing_key = "blabalabl";
    val_ptr = hashMapGet(&hash_map, non_existing_key, strlen(non_existing_key));
    if(val_ptr != NULL) 
    {
        return -1;
    }
    hashMapDestroy(&hash_map, NULL);
    TEST_END(4);
    
    return 0;
}
