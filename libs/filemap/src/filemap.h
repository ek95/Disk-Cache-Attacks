#ifndef _FILE_MAPPING_H_
#define _FILE_MAPPING_H_

#include <stdlib.h>
#ifdef _WIN32
#include "Windows.h"
#endif 

#define RANDOM_SOURCE_PATH "/dev/urandom"
#define FILE_COPY_BS (1*1024*1024ULL)
#define DEF_PAGE_SIZE 4096


// file specifiers
#define FILE_ACCESS_READ 0x00
#define FILE_ACCESS_WRITE 0x01
// only windows
#define FILE_USAGE_RANDOM 0x02
#define FILE_USAGE_SEQUENTIAL 0x04

// mapping specifiers
#define MAPPING_ACCESS_READ 0x00
#define MAPPING_ACCESS_WRITE 0x01
#define MAPPING_ACCESS_EXECUTE 0x02
#define MAPPING_PRIVATE 0x04
#define MAPPING_SHARED 0x08
// only windows
#define MAPPING_LARGE_PAGES 0x16


// usage advices 
// directly compatible with linux madvise and posix_fadvise
#define USAGE_NORMAL 0x00
#define USAGE_RANDOM 0x01
#define USAGE_SEQUENTIAL 0x02
#define USAGE_WILLNEED 0x03
#define USAGE_DONTNEED 0x04


#ifdef __linux
struct _FileMappingInternal_ {
    int fd_;
    unsigned char *page_status_;
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
    // architecture dependent
    struct _FileMappingInternal_ internal_;
} FileMapping;


void initFileMapping(FileMapping *file_mapping);
int mapFile(FileMapping *file_mapping, const char *file_path, int file_flags, int mapping_flag);
int adviseFileUsage(FileMapping *file_mapping, size_t offset, size_t len, int advice);
int fileMappingGetCacheStatus(FileMapping *file_mapping);
int fileMappingGetCacheStatusPage(FileMapping *file_mapping, int *status);
void closeMappingOnly(void *arg);
void closeFileMapping(void *arg);
int createRandomFile(char *filename, size_t size);


#endif
