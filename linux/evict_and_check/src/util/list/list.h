#ifndef _LIST_H_
#define _LIST_H_

#include <stddef.h>


typedef struct _ListNode_
{
    void *data_;
    struct _ListNode_ *next_;
    struct _ListNode_ *prev_;
} ListNode;

typedef struct _List_
{
    ListNode *head_;
    ListNode *tail_;
    size_t count_;
    size_t elem_size_;
} List;

typedef int (*ListCmpFn)(void *node, void *data);
typedef void (*ListDataCallbackArgFn)(void *data, void *arg);
typedef void (*ListDataCallbackFn)(void *data);


void listInit(List *list, size_t elem_size);
void listForEach(List *list, ListDataCallbackArgFn callback, void *arg);
ListNode *listSearchFirst(List *list, void *data, ListCmpFn cmp);
ListNode *listSearchLast(List *list, void *value, ListCmpFn cmp);
ListNode *listAppendNodeFront(List *list, ListNode *node);
ListNode *listAppendNodeBack(List *list, ListNode *node);
ListNode *listPopNode(List *list, ListNode *node);
ListNode *listAppendFront(List *list, void *data);
ListNode *listAppendBack(List *list, void *data);
ListNode *listGetIndex(List *list, size_t index);
List *listChain(List *list1, List *list2);
ListNode *listMoveNode(List *src_list, ListNode *node, List *dst_list);
void listDestroy(List *list, ListDataCallbackFn free_data);

#endif
