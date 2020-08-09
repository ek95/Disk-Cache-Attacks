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
#include "pageflags.h"


#define ARG_COUNT 1

#define TEST_FILE_PATH "test.so"
#define TEST_FILE_SIZE (2*1024*1024ULL)
#define TEST_FILE_TARGET_PAGE (0xAA)


size_t PAGE_SIZE = 0;


void usageError(char *program_name);


int main(int argc, char *argv[])
{
  int ret = 0;
  struct stat file_stat;
  FileMapping file_mapping;
  PageFlagsFd pageflags_fd;
  KPageFlagsEntry page_flags;
  char choice;
  volatile uint8_t tmp = 0;
  uint8_t *addr = NULL;
  unsigned char page_status = 0;
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


  // open page flags
  if(openPageFlagsFd(&pageflags_fd) != 0)
  {
    printf("Error (%s) at openPageFlags\n", strerror(errno));
    goto error;
  }


  printf("Flush file page...\n");
  // flush file page
  madvise(file_mapping.addr_ + TEST_FILE_TARGET_PAGE * PAGE_SIZE, PAGE_SIZE, MADV_DONTNEED);
  posix_fadvise(file_mapping.fd_, TEST_FILE_TARGET_PAGE * PAGE_SIZE, PAGE_SIZE, POSIX_FADV_DONTNEED);


  addr = file_mapping.addr_ + TEST_FILE_TARGET_PAGE * PAGE_SIZE;
  // run
  while(1)
  {
    printf("q -> quit, a -> access, r -> read, p -> print pageflags, f -> flush\n");
    printf("> ");
    if(scanf("%c", &choice) == EOF)
    {
      printf("Faulty input, exiting...\n");
      break;
    }

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
        printf("Warning: pread was not successfull...");
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
    else if(choice == 'f')
    {
      madvise(file_mapping.addr_ + TEST_FILE_TARGET_PAGE * PAGE_SIZE, PAGE_SIZE, MADV_DONTNEED);
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
