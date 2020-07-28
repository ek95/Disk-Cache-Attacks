#define _GNU_SOURCE 

#include "filemap.h"
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/limits.h>
#include <errno.h>


static size_t PAGE_SIZE = 0;


void initFileMapping(FileMapping *file_mapping)
{
    memset(file_mapping, 0, sizeof(FileMapping));
    file_mapping->fd_ = -1;
}


// all functions that might fail set errno so errno can be used to get more info
int mapFile(FileMapping *file_mapping, const char *file_path, int open_flags, int mmap_prot, int mmap_flags)
{
    struct stat file_stat;

    // open file
    file_mapping->fd_ = open(file_path, open_flags);
    if(file_mapping->fd_ < 0)
    {
        goto error;
    }

    if(fstat(file_mapping->fd_, &file_stat) != 0)
    {
        goto error;
    }

    // fetch system PAGE_SIZE if not done alreay
    if(PAGE_SIZE == 0)
    {
        long res = sysconf(_SC_PAGESIZE);
        PAGE_SIZE = (res != -1) ? res : DEF_PAGE_SIZE;
    }


    file_mapping->size_ = file_stat.st_size;
    file_mapping->size_pages_ = (file_stat.st_size + PAGE_SIZE - 1) / PAGE_SIZE;
    // NOTE file mapping structure may be extended to support custom offset + size
    file_mapping->addr_ =
        mmap(NULL, file_mapping->size_ , mmap_prot, mmap_flags, file_mapping->fd_, 0);
    if(file_mapping->addr_ == MAP_FAILED)
    {
        goto error;
    }

    return 0;

error:

    closeFileMapping(file_mapping);
    return -1;
}


void closeFileMapping(void *arg)
{
    FileMapping* file_mapping = arg;

    if(file_mapping->addr_ != NULL)
    {
        munmap(file_mapping->addr_, file_mapping->size_);
        file_mapping->addr_ = NULL;
    }
    if(file_mapping->fd_ >= 0)
    {
        close(file_mapping->fd_);
        file_mapping->fd_ = -1;
    }
    free(file_mapping->page_status_);
}


// all functions that might fail set errno so errno can be used to get more info
int createRandomFile(char* filename, size_t size)
{
    int fd;
    struct stat file_stat;
    struct statvfs filesys_stat;
    char cwd[PATH_MAX] = { 0 };

    // open file or if already exists check if current size, else overwrite
    fd = open(filename, O_CREAT | O_WRONLY | O_EXCL, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if(fd < 0)
    {
        if(errno != EEXIST)
        {
            return -1;
        }

        // file already exists check size
        if(stat(filename, &file_stat) != 0)
        {
            return -1;
        }
        // too small, recreate
        if(file_stat.st_size < size)
        {
            close(fd);
            fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
            if(fd < 0)
            {
                return -1;
            }
        }
        // right size exit
        else
        {
            return 0;
        }
    }

    // create new file
    // get working direcory
    if(getcwd(cwd, sizeof(cwd)) == NULL)
    {
        return -1;
    }
    // check if enough space disk space
    if(statvfs(cwd, &filesys_stat) != 0)
    {
        return -1;
    }

    // sanity checks
    size_t free_disk = filesys_stat.f_bsize * filesys_stat.f_bavail;
    if(free_disk < size)
    {
        errno = ENOSPC;
        return -1;
    }

    // try fallocate first, if it fails fall back to the much slower file copy
    if(fallocate(fd, 0, 0, size) != 0)
    {
        // fallocate failed, fall back to creating eviction file from /dev/urandom
        close(fd);

        FILE* rnd_file = fopen(RANDOM_SOURCE_PATH, "rb");
        if(rnd_file == NULL)
        {
            return -1;
        }
        FILE* target_file = fopen(filename, "wb");
        if(target_file == NULL)
        {
            return -1;
        }
        size_t bs = FILE_COPY_BS;
        size_t rem = size;

        char* block = malloc(bs);
        if(block == NULL)
        {
            return -1;
        }

        while(rem)
        {
            if(fread(block, bs, 1, rnd_file) != 1)
            {
                fclose(rnd_file);
                fclose(target_file);
                free(block);
                return -1;
            }
            if(fwrite(block, bs, 1, target_file) != 1)
            {
                fclose(rnd_file);
                fclose(target_file);
                free(block);
                return -1;
            }
            if(rem >= bs)
            {
                rem -= bs;
            }
            else
            {
                rem = 0;
            }
        }

        fclose(rnd_file);
        fclose(target_file);
        free(block);
    }

    close(fd);
    return 0;
}
