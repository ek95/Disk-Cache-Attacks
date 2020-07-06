#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <limits.h>


size_t PAGE_SIZE = 0;


void usageError(char *program_name);


int main(int argc, char *argv[])
{
  int ret = 0;
  char *endptr = NULL;
  size_t target_page = 0;
  size_t access_period = 0;
  size_t access_count = 0;
  struct timespec wait_time;
  int fd = -1;
  struct stat file_stat;
  void *addr = MAP_FAILED;
  volatile uint8_t tmp = 0;
  (void) tmp;


  if(argc != 5)
  {
    usageError(argv[0]);
    goto error;
  }

  PAGE_SIZE = sysconf(_SC_PAGESIZE);
  if(PAGE_SIZE == -1)
  {
    printf("Error (%s) at sysconf.\n", strerror(errno));
    goto error;
  }


  target_page = strtoul(argv[2], &endptr, 10);
  if(endptr == argv[2] || *endptr != 0 || (target_page == ULONG_MAX && errno == ERANGE))
  {
    usageError(argv[0]);
    goto error;
  }
  access_period = strtoul(argv[3], &endptr, 10);
  if(endptr == argv[3] || *endptr != 0 || (access_period == ULONG_MAX && errno == ERANGE))
  {
    usageError(argv[0]);
    goto error;
  }
  access_count = strtoul(argv[4], &endptr, 10);
  if(endptr == argv[4] || *endptr != 0 || (access_count == ULONG_MAX && errno == ERANGE))
  {
    usageError(argv[0]);
    goto error;
  }

  wait_time.tv_sec = access_period / 1000UL;
  wait_time.tv_nsec = (access_period % 1000UL) * 1000000UL;


  printf("Mapping file %s into memory...\n", argv[1]);
  fd = open(argv[1], O_RDONLY);
  if(fd < 0)
  {
    printf("Error (%s) at opening file %s.\n", strerror(errno), argv[1]);
    goto error;
  }
  if(fstat(fd, &file_stat))
  {
    printf("Error (%s) at fstat.\n", strerror(errno));
    goto error;
  }
  if(target_page >= (file_stat.st_size + PAGE_SIZE - 1) / PAGE_SIZE)
  {
    printf("Error: Page offset is out of bound.\n");
    goto error;
  }
  addr = mmap(NULL, file_stat.st_size, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
  if(addr == MAP_FAILED)
  {
    printf("Error (%s) at mmap.\n", strerror(errno));
    goto error;
  }


  for(size_t access_nr = 0; access_nr < access_count; access_nr++)
  {
    printf("%zu. Access\n", access_nr + 1);
    tmp = *((uint8_t *) addr + target_page * PAGE_SIZE);

    nanosleep(&wait_time, NULL);
  }


  goto cleanup;
error:

  ret = -1;

cleanup:

  if(addr != MAP_FAILED)
  {
    munmap(addr, file_stat.st_size);
  }
  if(fd >= 0)
  {
    close(fd);
  }

  return ret;
}


void usageError(char *program_name)
{
  printf("Usage: %s [file to map] [page offset] [access period in ms] [access count].\n", program_name);
}
