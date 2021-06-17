#ifndef _LIST_H_
#define _LIST_H_

#include <stddef.h>


#define LIST_FE_OK 0
#define LIST_FE_BREAK 1


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

typedef int (*ListCmpFn)(void *data, void *cmp_data);
typedef int (*ListDataCallbackFn)(void *data);
typedef int (*ListDataCallbackArgFn)(void *data, void *arg);


void listInit(List *list, size_t elem_size);
ListNode *listGetIndex(List *list, size_t index);
int listForEach(List *list, ListDataCallbackArgFn callback, void *arg);
int listForEachSimple(List *list, ListDataCallbackFn callback);
ListNode *listSearchFirst(List *list, void *data, ListCmpFn cmp);
ListNode *listSearchLast(List *list, void *value, ListCmpFn cmp);
ListNode *listAppendNodeFront(List *list, ListNode *node);
ListNode *listAppendNodeBack(List *list, ListNode *node);
ListNode *listAppendFront(List *list, void *data);
ListNode *listAppendBack(List *list, void *data);
ListNode *listPopNode(List *list, ListNode *node);
ListNode *listMoveNode(List *src_list, ListNode *node, List *dst_list);
List *listChain(List *list1, List *list2);
void listDestroy(List *list, ListDataCallbackFn free_data);

#endif
