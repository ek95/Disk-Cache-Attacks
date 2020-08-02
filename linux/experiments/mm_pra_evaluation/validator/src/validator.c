#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include "filemap.h"


#define ARG_COUNT 2
#define MODE_ARG 1

#define TEST_FILE_PATH "test.so"
#define TEST_FILE_SIZE (2*1024*1024ULL)
#define TEST_FILE_TARGET_PAGE (0xAA)

#define READ_RO_FILE_PAGE_USER 1
#define MAPPED_RO_FILE_PAGE_USER 2
#define VOL_RELEASED_RO_FILE_PAGE 3
#define VOL_RELEASED_MAPPED_RO_FILE_PAGE 4
#define VOL_RELEASED_DIRTY_MAPPING_PAGE 5

#define WAIT_TIME_S 1


size_t PAGE_SIZE = 0;


void usageError(char *program_name);


int main(int argc, char *argv[])
{
  int ret = 0;
  int mode = 0;
  struct stat file_stat;
  FileMapping file_mapping;
  volatile uint8_t tmp = 0;
  uint8_t *addr = NULL;
  unsigned char page_status = 0;
  struct timespec wait_time = {
    .tv_sec = WAIT_TIME_S,
    .tv_nsec = 0
  };
  (void) tmp;


  initFileMapping(&file_mapping);

  if(argc != ARG_COUNT)
  {
    usageError(argv[0]);
    goto error;
  }


  // get system page size
  PAGE_SIZE = sysconf(_SC_PAGESIZE);
  if(PAGE_SIZE == -1)
  {
    printf("Error (%s) at sysconf\n", strerror(errno));
    goto error;
  }


  mode = atoi(argv[MODE_ARG]);

  if(mode == READ_RO_FILE_PAGE_USER ||
     mode == MAPPED_RO_FILE_PAGE_USER ||
     mode == VOL_RELEASED_RO_FILE_PAGE ||
     mode == VOL_RELEASED_MAPPED_RO_FILE_PAGE)
  {
    // create test file
    if(createRandomFile(TEST_FILE_PATH, TEST_FILE_SIZE) != 0)
    {
      printf("Error (%s) at createRandomFile\n", strerror(errno));
      goto error;
    }

    // open file
    file_mapping.fd_ = open(TEST_FILE_PATH, O_RDONLY);
    if(file_mapping.fd_ < 0)
    {
        printf("Error (%s) at open\n", strerror(errno));
        goto error;
    }

    // advise no readahead
    posix_fadvise(file_mapping.fd_, 0, 0, POSIX_FADV_RANDOM);

    // get file stat
    if(fstat(file_mapping.fd_, &file_stat) != 0)
    {
        printf("Error (%s) at fstat\n", strerror(errno));
        goto error;
    }
  }

  if(mode == READ_RO_FILE_PAGE_USER || mode == VOL_RELEASED_RO_FILE_PAGE)
  {
    if(pread(file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }

    if(mode == VOL_RELEASED_RO_FILE_PAGE)
    {
      nanosleep(&wait_time, NULL);
      posix_fadvise(file_mapping.fd_, TEST_FILE_TARGET_PAGE * PAGE_SIZE, PAGE_SIZE, POSIX_FADV_DONTNEED);
      close(file_mapping.fd_);
    }
  }
  else if(mode == MAPPED_RO_FILE_PAGE_USER || mode == VOL_RELEASED_MAPPED_RO_FILE_PAGE)
  {
    // map file
    file_mapping.size_ = file_stat.st_size;
    file_mapping.size_pages_ = (file_stat.st_size + PAGE_SIZE - 1) / PAGE_SIZE;
    file_mapping.addr_ =
        mmap(NULL, file_mapping.size_ , PROT_READ, MAP_PRIVATE, file_mapping.fd_, 0);
    if(file_mapping.addr_ == MAP_FAILED)
    {
        printf("Error (%s) at mmap\n", strerror(errno));
        goto error;
    }

    if(mode == VOL_RELEASED_MAPPED_RO_FILE_PAGE)
    {
      printf("reached\n");
      nanosleep(&wait_time, NULL);
      madvise(file_mapping.addr_ + TEST_FILE_TARGET_PAGE * PAGE_SIZE, PAGE_SIZE, MADV_DONTNEED);
      munmap(file_mapping.addr_, file_mapping.size_);
    }
  }
  else if(mode == VOL_RELEASED_DIRTY_MAPPING_PAGE)
  {
    addr = mmap(NULL, PAGE_SIZE , PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if(file_mapping.addr_ == MAP_FAILED)
    {
        printf("Error (%s) at mmap\n", strerror(errno));
        goto error;
    }
    *addr = 1;

    nanosleep(&wait_time, NULL);
    madvise(addr, PAGE_SIZE, MADV_DONTNEED);
    munmap(file_mapping.addr_, file_mapping.size_);
  }


  printf("Press key to exit...\n");
  getchar();


  goto cleanup;
error:

  ret = -1;

cleanup:

  closeFileMapping(&file_mapping);
  return ret;
}


void usageError(char *program_name)
{
  printf("Usage: %s [mode].\n", program_name);
  printf("\t1\tRead ro test file page\n");
  printf("\t2\tMap ro test file page\n");
  printf("\t3\tRead ro test file page + release voluntary\n");
  printf("\t4\tMap ro test file page + release voluntary\n");
  printf("\t5\tMap dirty test page + release voluntary\n");
}
