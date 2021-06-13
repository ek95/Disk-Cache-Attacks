#include "list.h"
#include <stdlib.h>
#include <string.h>


void listInit(List *list, size_t elem_size)
{
    list->head_ = NULL;
    list->tail_ = NULL;
    list->count_ = 0;
    list->elem_size_ = elem_size;
}


ListNode *listGetIndex(List *list, size_t index)
{
    ListNode *node = list->head_;
    size_t current_index = 0;

    while(node != NULL && current_index < index)
    {
        node = node->next_;
        current_index++;
    }

    return node;
}


void listForEach(List *list, ListDataCallbackArgFn callback, void *arg)
{
    ListNode *node = list->head_;

    while(node != NULL)
    {
        callback(node->data_, arg);

        node = node->next_;
    }
}

void listForEachSimple(List *list, ListDataCallbackFn callback)
{
    ListNode *node = list->head_;

    while(node != NULL)
    {
        callback(node->data_);

        node = node->next_;
    }
}

ListNode *listSearchFirst(List *list, void *data, ListCmpFn cmp)
{
    ListNode *node = list->head_;
    
    while(node != NULL)
    {
        if(cmp(node->data_, data) == 1)
        {
            return node;
        }

        node = node->next_;
    }

    return NULL;
}


ListNode *listSearchLast(List *list, void *data, ListCmpFn cmp)
{
    ListNode *node = list->tail_;

    while(node != NULL)
    {
        if(cmp(node->data_, data) == 1)
        {
            return node;
        }

        node = node->prev_;
    }

    return NULL;
}


ListNode *listAppendNodeFront(List *list, ListNode *node)
{
    // list is empty
    if(list->head_ == NULL)
    {
        list->head_ = node;
        list->tail_ = node;
    }
    else 
    {
        // prev
        list->head_->prev_ = node;
        // next
        node->next_ = list->head_;
        list->head_ = node;
    }
    
    list->count_++;
    return node;
}


ListNode *listAppendNodeBack(List *list, ListNode *node) 
{
    // list is empty
    if(list->head_ == NULL)
    {
        list->head_ = node;
        list->tail_ = node;
    }
    else 
    {
        // next
        list->tail_->next_ = node;
        // prev
        node->prev_ = list->tail_;
        list->tail_ = node;
    }
    
    list->count_++;
    return node;
}


ListNode *listAppendFront(List *list, void *data)
{
    ListNode *new_node = NULL;

    new_node = calloc(1, sizeof(ListNode));
    if(new_node == NULL)
    {
        return NULL;
    }

    new_node->data_ = malloc(list->elem_size_);
    if(new_node->data_ == NULL)
    {
        free(new_node);
        return NULL;
    }
    memcpy(new_node->data_, data, list->elem_size_);

    return listAppendNodeFront(list, new_node);
}


ListNode *listAppendBack(List *list, void *data)
{
    ListNode *new_node = NULL;

    new_node = calloc(1, sizeof(ListNode));
    if(new_node == NULL)
    {
        return NULL;
    }

    new_node->data_ = malloc(list->elem_size_);
    if(new_node->data_ == NULL)
    {
        free(new_node);
        return NULL;
    }
    memcpy(new_node->data_, data, list->elem_size_);

    return listAppendNodeBack(list, new_node);
}


ListNode *listPopNode(List *list, ListNode *node) 
{    
    // only one node in list
    if(node->prev_ == NULL && node->next_ == NULL) 
    {
        list->head_ = NULL;
        list->tail_ = NULL;
    }
    // node is head
    else if(node->prev_ == NULL)
    {
        // next node becomes head
        list->head_ = node->next_;
    }
    // node is tail 
    else if(node->next_ == NULL) 
    {
        // previous node becomes tail
        list->tail_ = node->prev_;
    }
    // node is between two nodes
    else
    {        
        node->next_->prev_ = node->prev_;
        node->prev_->next_ = node->next_;
    }
    
    // reduce list count
    list->count_--;
    
    // clear node links
    node->next_ = NULL;
    node->prev_ = NULL;
    
    
    return node;
}


ListNode *listMoveNode(List *src_list, ListNode *node, List *dst_list)
{
    listPopNode(src_list, node);
    listAppendNodeBack(dst_list, node);
    return node;
}


List *listChain(List *list1, List *list2) 
{
    // list 2 empty
    if(list2->head_ == NULL)
    {
        return list1;
    }
    
    // list 1 empty
    if(list1->head_ == NULL)
    {
        *list1 = *list2;
    }
    // normal case
    else 
    {
        list1->tail_->next_ = list2->head_;
        list2->head_->prev_ = list1->tail_;
        list1->tail_ = list2->tail_;
    }
    
    // empty list 2 
    list2->head_ = NULL;
    list2->tail_ = NULL;
    list2->count_ = 0;
    
    return list1;
}


void listDestroy(List *list, ListDataCallbackFn free_data)
{
    ListNode *node = list->head_;
    ListNode *tmp = list->head_;

    while(node != NULL)
    {
        if(node->data_ != NULL)
        {
            if(free_data != NULL)
            {
                free_data(node->data_);
            }
            
            free(node->data_);
        }

        tmp = node->next_;
        free(node);
        node = tmp;
    }

    list->head_ = NULL;
    list->tail_ = NULL;
    list->count_ = 0;
}