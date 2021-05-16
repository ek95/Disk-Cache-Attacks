#define _GNU_SOURCE
#define _DEFAULT_SOURCE

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
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include "filemap.h"
#include "pageflags.h"
#include "tsc_bench.h"

// mincore fixed, preadv2 still works, read nonblock does not see man, access time does 
#define _MINCORE_
//#define _PREADV2_
//#define _READ_NONBLOCK_
//#define _ACCESS_TIME_
#define DISK_ACCESS_THRESHOLD_NS (1 * 1000UL) 

#define ARG_COUNT 1

#define TEST_FILE_PATH "test.so"
#define TEST_FILE_SIZE (2*1024*1024ULL)
#define TEST_FILE_TARGET_PAGE (0xAA)


size_t PAGE_SIZE = 0;


void usageError(char *program_name);


int main(int argc, char *argv[])
{
  int ret = 0;
  ssize_t ret_pread = 0;
  FileMapping file_mapping;
  PageFlagsFd pageflags_fd;
  KPageFlagsEntry page_flags;
  char choice;
  volatile uint8_t tmp = 0;
  uint8_t *addr = NULL;
  unsigned char page_status = 0;
  struct iovec io_range = {0};
  (void) ret_pread;
  (void) tmp;
  (void) io_range;


  initFileMapping(&file_mapping);

  if(argc != ARG_COUNT)
  {
    usageError(argv[0]);
    goto error;
  }


#ifdef _ACCESS_TIME_
  if(tsc_bench_init(0) != 0) {
    printf("Error at tsc_bench_init\n");
    goto error;
  }
#endif


  // get system page size
  PAGE_SIZE = sysconf(_SC_PAGESIZE);
  if(PAGE_SIZE == -1)
  {
    printf("Error (%s) at sysconf\n", strerror(errno));
    goto error;
  }

  // open page flags
  if(openPageFlagsFd(&pageflags_fd) != 0)
  {
    printf("Error (%s) at openPageFlags\n", strerror(errno));
    printf("Pageflags can not be used...\n");
  }

  // create test file
  if(createRandomFile(TEST_FILE_PATH, TEST_FILE_SIZE) != 0)
  {
    printf("Error (%s) at createRandomFile\n", strerror(errno));
    goto error;
  }


  // map test file
  if(mapFile(&file_mapping, TEST_FILE_PATH, O_RDONLY, PROT_READ /*| PROT_EXEC*/, MAP_PRIVATE) != 0)
  {
      printf("Error (%s) at mapFile for: %s ...\n", strerror(errno), TEST_FILE_PATH);
      goto error;
  }
#ifdef _READ_NONBLOCK_
  int flags = fcntl(file_mapping.fd_, F_GETFL, 0);
  if(flags == -1) {
    printf("Error (%s) at fcntl ...\n", strerror(errno));
    goto error;  
  }
  if(fcntl(file_mapping.fd_, F_SETFL, flags | O_NONBLOCK) == -1) {
    printf("Error (%s) at fcntl ...\n", strerror(errno));
    goto error;
  }
#endif


  printf("Trying to flush file page...\n");
  // flush file page
  madvise((uint8_t *) file_mapping.addr_ + TEST_FILE_TARGET_PAGE * PAGE_SIZE, PAGE_SIZE, MADV_DONTNEED);
  posix_fadvise(file_mapping.fd_, TEST_FILE_TARGET_PAGE * PAGE_SIZE, PAGE_SIZE, POSIX_FADV_DONTNEED);


  addr = (uint8_t *) file_mapping.addr_ + TEST_FILE_TARGET_PAGE * PAGE_SIZE;
  io_range.iov_base = (void *) &tmp;
  io_range.iov_len = 1;
  // run
  while(1)
  {
    printf("\nq -> quit, a -> access, r -> read, p -> print pageflags, s -> status, f -> flush\n");
    printf("> ");
    do
    {
      if((choice = getchar()) == EOF)
      {
        printf("Faulty input, exiting...\n");
        goto error;
      }
    } while(choice == '\n');

    if(choice == 'q')
    {
      break;
    }
    else if(choice == 'a')
    {
      tmp = *addr;
    }
    else if(choice == 'r')
    {
      if(pread(file_mapping.fd_, (uint8_t *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1)
      {
        printf("Warning: pread was not successfull...\n");
      }
    }
    else if(choice == 'p')
    {
      if(getKPageFlagsEntryVpn(&pageflags_fd, &page_flags, (size_t) addr / PAGE_SIZE) != 0)
      {
        printf("Error (%s) at getKPageFlagsEntryVpn, continuing\n", strerror(errno));
        continue;
      }

      printf("referenced: %u\n", page_flags.referenced);
      printf("lru: %u\n", page_flags.lru);
      printf("active: %u\n", page_flags.active);
      printf("mmap: %u\n", page_flags.mmap);
      printf("anon: %u\n", page_flags.anon);
      printf("idle: %u\n", page_flags.idle);
    }
    else if(choice == 's')
    {
      page_status = 0;
#ifdef _MINCORE_
      if(mincore(addr, PAGE_SIZE, &page_status) != 0)
      {
        printf("Error (%s) at mincore...\n", strerror(errno));
        continue;
      }
#elif defined(_PREADV2_)
      ret_pread = preadv2(file_mapping.fd_, &io_range, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE, RWF_NOWAIT);
      if(ret_pread == -1)
      {
        if(errno == EAGAIN)
        {
          page_status = 0;
        }
        else 
        {
          printf("Error (%s) at preadv2...\n", strerror(errno));
          continue;
        }
      }
      else 
      {
        page_status = 1;
      }
#elif defined(_READ_NONBLOCK_)
      ret_pread = pread(file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE);
      if(ret_pread == -1)
      {
        if(errno == EAGAIN)
        {
          page_status = 0;
        }
        else 
        {
          printf("Error (%s) at pread...\n", strerror(errno));
          continue;
        }
      }
      else 
      {
        page_status = 1;
      }
#elif defined(_ACCESS_TIME_) 
      uint64_t start_cycle = 0, end_cycle = 0;
      TSC_BENCH_START(start_cycle);
      tmp = *addr;
      TSC_BENCH_STOP(end_cycle);
      uint64_t access_time = tsc_bench_get_runtime_ns(start_cycle, end_cycle);
      printf("Access time: %zu ns\n", access_time);
      page_status = access_time < DISK_ACCESS_THRESHOLD_NS;
#else 
	#error You have to select a software method to get the page status!
#endif
      printf("Status: %d\n", page_status & 1);
    }
    else if(choice == 'f')
    {
      madvise((uint8_t *) file_mapping.addr_ + TEST_FILE_TARGET_PAGE * PAGE_SIZE, PAGE_SIZE, MADV_DONTNEED);
      posix_fadvise(file_mapping.fd_, TEST_FILE_TARGET_PAGE * PAGE_SIZE, PAGE_SIZE, POSIX_FADV_DONTNEED);
    }
  }


  goto cleanup;
error:

  ret = -1;

cleanup:

  closePageFlagsFd(&pageflags_fd);
  closeFileMapping(&file_mapping);
  return ret;
}


void usageError(char *program_name)
{
  printf("Usage: %s\n", program_name);
}
