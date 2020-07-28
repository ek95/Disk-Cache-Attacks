#ifndef _FILE_MAPPING_H_
#define _FILE_MAPPING_H_

#include <stdlib.h>


#define RANDOM_SOURCE_PATH "/dev/urandom"
#define FILE_COPY_BS (1*1024*1024ULL)
#define DEF_PAGE_SIZE 4096


typedef struct _FileMapping_
{
    int fd_;
    void *addr_;
    size_t size_;
    size_t size_pages_;
    unsigned char *page_status_;
} FileMapping;


void initFileMapping(FileMapping *file_mapping);
int mapFile(FileMapping *file_mapping, const char *file_path, int open_flags, int mmap_prot, int mmap_flags);
void closeFileMapping(void *arg);
int createRandomFile(char *filename, size_t size);


#endif
