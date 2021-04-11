#ifndef _PAGEFLAGS_H_
#define _PAGEFLAGS_H_

#include <stdint.h>
#include <stddef.h>


#define MAX_PAGEMAP_PATH_LEN 255
#define PAGEMAP_PATH_TEMPLATE "/proc/%d/pagemap"
#define KPAGEFLAGS "/proc/kpageflags"
#define PAGE_FLAGS_FD_STATIC_INIT {-1, -1}


typedef struct {
  int pagemap_fd_;
  int kpageflags_fd_;
} PageFlagsFd;


// no padding for better alignment
#pragma pack(push, 1)

typedef struct {
  uint64_t pfn : 55;
  uint64_t exclusively_mapped : 1;
} PresentInfo;

typedef struct {
  uint64_t swap_type : 5;
  uint64_t swap_offset : 50;
  uint64_t exclusively_mapped : 1;
} SwapInfo;

typedef union {
  PresentInfo present_info;
  SwapInfo swap_info;
} PfnSwapInfo;

typedef struct {
  PfnSwapInfo present_swap;
  uint64_t zero : 4;
  uint64_t soft_dirty : 1;
  uint64_t file_page : 1;
  uint64_t swapped : 1;
  uint64_t present : 1;
} PageMapEntry;

typedef struct {
  uint64_t locked : 1;
  uint64_t error : 1;
  uint64_t referenced : 1;
  uint64_t uptodate : 1;
  uint64_t dirty : 1;
  uint64_t lru : 1;
  uint64_t active : 1;
  uint64_t slab : 1;
  uint64_t writeback : 1;
  uint64_t reclaim : 1;
  uint64_t buddy : 1;
  uint64_t mmap : 1;
  uint64_t anon : 1;
  uint64_t swapcache : 1;
  uint64_t swapbacked : 1;
  uint64_t compound_head : 1;
  uint64_t compound_tail : 1;
  uint64_t huge : 1;
  uint64_t unevictable : 1;
  uint64_t hwpoison : 1;
  uint64_t nopage : 1;
  uint64_t ksm : 1;
  uint64_t thp : 1;
  uint64_t offline : 1;
  uint64_t zero_page : 1;
  uint64_t idle : 1;
  uint64_t pgtable : 1;
  uint64_t unused : 37;
} KPageFlagsEntry;

#pragma pack(pop)


int openPageFlagsFd(PageFlagsFd *pageflags_fd);
int pageFlagsFdValid(PageFlagsFd *pageflags_fd);
void closePageFlagsFd(PageFlagsFd *pageflags_fd);
int getPagemapEntryVpn(PageFlagsFd *pageflags_fd, PageMapEntry *entry, size_t vpn);
int getKPageFlagsEntryPfn(PageFlagsFd *pageflags_fd, KPageFlagsEntry *entry, size_t pfn);
int getKPageFlagsEntryVpn(PageFlagsFd *pageflags_fd, KPageFlagsEntry *page_flags, size_t vpn);


#endif
