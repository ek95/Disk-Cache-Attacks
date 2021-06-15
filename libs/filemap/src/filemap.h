#ifndef _FILE_MAPPING_H_
#define _FILE_MAPPING_H_

#include <stdlib.h>
#include <stdint.h>
#ifdef _WIN32
#include "Windows.h"
#include "psapi.h"
#endif 


// file specifiers
#define FILE_ACCESS_READ 0x01
#define FILE_ACCESS_WRITE 0x02
#define FILE_NOATIME 0x04
// only windows
#define FILE_ACCESS_EXECUTE (0x01 << 16)
#define FILE_USAGE_RANDOM (0x02 << 16)
#define FILE_USAGE_SEQUENTIAL (0x04 << 16)

// mapping specifiers
#define MAPPING_ACCESS_READ 0x01
#define MAPPING_ACCESS_WRITE 0x02
#define MAPPING_ACCESS_EXECUTE 0x04
#define MAPPING_PRIVATE 0x08
#define MAPPING_SHARED 0x10
// only linux
#define MAPPING_NORESERVE (0x01 << 8)
// only windows
#define MAPPING_LARGE_PAGES (0x01 << 16)

// query file cache state sources
// shared 
#define FC_SOURCE_ACCESS 0x00
// linux
#define FC_SOURCE_MINCORE 0x100
#define FC_SOURCE_PREADV2 0x101
// windows
#define FC_SOURCE_QUERY_WORKING_SET 0x200

// usage advices 
// directly compatible with linux madvise and posix_fadvise
#define USAGE_NORMAL 0x00
#define USAGE_RANDOM 0x01
#define USAGE_SEQUENTIAL 0x02
#define USAGE_WILLNEED 0x03
#define USAGE_DONTNEED 0x04

#define DISK_ACCESS_THRESHOLD_NS (1 * 1000UL) 

#define RANDOM_SOURCE_PATH "/dev/urandom"
#define FILE_COPY_BS (1 * 1024 * 1024ULL)
#define DEF_PAGE_SIZE 4096


#ifdef __linux
struct _FileMappingInternal_ {
    int fd_;
};
#elif defined(_WIN32)
struct _FileMappingInternal_ {
  HANDLE file_handle_;
  HANDLE mapping_handle_;
  PSAPI_WORKING_SET_EX_INFORMATION *page_status_;
};
#else 
#error OS not supported!
#endif 


typedef struct _FileMapping_
{
    void *addr_;
    size_t size_;
    size_t size_pages_;
    uint8_t *pages_cache_status_;
    // architecture dependent
    struct _FileMappingInternal_ internal_;
} FileMapping;

typedef int (*FcStateFn)(FileMapping *file_mapping, size_t offset, size_t len, uint8_t *vec);


void initFileMapping(FileMapping *file_mapping);
int mapFile(FileMapping *file_mapping, const char *file_path, int file_flags, int mapping_flags);
int mapAnon(FileMapping *file_mapping, size_t size, int mapping_flags);
int adviseFileUsage(FileMapping *file_mapping, size_t offset, size_t len, int advice);
int getCacheStatusFile(FileMapping *file_mapping);
int getCacheStatusFilePage(FileMapping *file_mapping, size_t offset, uint8_t *status);
void freeFileCacheStatus(FileMapping *file_mapping);
void closeFileOnly(void *arg);
void closeMappingOnly(void *arg);
void closeFileMapping(void *arg);
int createRandomFile(char *filename, size_t size);
int changeFcStateSource(int source);

#endif
