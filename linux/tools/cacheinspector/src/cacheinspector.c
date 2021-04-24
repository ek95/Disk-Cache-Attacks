#define _GNU_SOURCE
#define _DEFAULT_SOURCE

// needs tsc_freq_khz kernel module!
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include "filemap.h"
#include "tsc_bench.h"
#include "pageflags.h"


#define ARG_COUNT 2
#define CLUSTER_PAGES 16
#define CLUSTERS_PER_LINE 4
#define INPUT_LINE_SIZE 255
#define DISK_ACCESS_THRESHOLD_NS (1 * 1000UL) 


typedef int (*PcStateFn)(int fd, void *addr, size_t offset, size_t length, unsigned char *vec);


void usageError(char *program_name);
int doPcStateMincore(int fd, void *addr, size_t offset, size_t length, unsigned char *vec);
int doPcStatePreadV2(int fd, void *addr, size_t offset, size_t length, unsigned char *vec);
int doPcStateAccess(int fd, void *addr, size_t offset, size_t length, unsigned char *vec);
void printPcState(unsigned char *pages_status, unsigned char *last_pages_status, size_t range, size_t print_start_addr);


size_t PAGE_SIZE = 0;
const PcStateFn PC_STATE_FNS[] = {doPcStateMincore, doPcStatePreadV2, doPcStateAccess};
PcStateFn active_pc_state_fn = doPcStateMincore;


int main(int argc, char *argv[])
{
  int ret = 0;
  FileMapping file_mapping;
  unsigned char *pages_status = NULL;
  unsigned char *last_pages_status = NULL;
  char choice = 0;
  char input[INPUT_LINE_SIZE] = {0};
  char last_input[INPUT_LINE_SIZE] = {0};
  PageFlagsFd pageflags_fd = PAGE_FLAGS_FD_STATIC_INIT;
  KPageFlagsEntry page_flags;


  initFileMapping(&file_mapping);

  if(argc != ARG_COUNT)
  {
    usageError(argv[0]);
    goto error;
  }


  // init performance counter timing library
  if(tsc_bench_init(0) != 0) {
    printf("Error at tsc_bench_init\n");
    goto error;
  }

  // open page flags
  if(openPageFlagsFd(&pageflags_fd) != 0)
  {
    printf("Error (%s) at openPageFlags\n", strerror(errno));
    printf("Pageflags can not be used, restart with root permissions if wanted...\n");
  }

  // get system page size
  PAGE_SIZE = sysconf(_SC_PAGESIZE);
  if(PAGE_SIZE == -1)
  {
    printf("Error (%s) at sysconf\n", strerror(errno));
    goto error;
  }

  // map test file
  if(mapFile(&file_mapping, argv[1], O_RDONLY, PROT_READ, MAP_PRIVATE) != 0)
  {
      printf("Error (%s) at mapFile for: %s ...\n", strerror(errno), argv[0]);
      goto error;
  }
  // avoid readahead
  posix_fadvise(file_mapping.fd_, 0, 0, POSIX_FADV_RANDOM);
  madvise(file_mapping.addr_, file_mapping.size_pages_ * PAGE_SIZE, MADV_RANDOM);

  // alloc page status array
  pages_status = malloc(file_mapping.size_pages_);
  last_pages_status = calloc(file_mapping.size_pages_, sizeof(uint8_t));
  if(pages_status == NULL || last_pages_status == NULL) {
    printf("Error (%s) at malloc\n", strerror(errno));
    goto error;
  }


  // run
  while(1)
  {
    printf("\nq -> quit\n"\
           "a <offset in pages as hex> <range in pages as hex> -> access pages\n"\
           "m <offset in pages as hex> <range in pages as hex> <advice as hex> -> tell kernel how region is used\n"\
           "p|d <offset in pages as hex> <range in pages as hex> -> p: print page status, d: shows diff with last status\n"\
           "c <page cache status source: 0 - mincore, 1 - preadv2, 2 - access time> -> change page cache status source\n"\
           "s <offset in pages as hex> -> shows vm flags of page\n");
    printf("> ");
    if(fgets(input, INPUT_LINE_SIZE, stdin) == NULL) 
    {
      printf("Faulty input, exiting...\n");
      goto error;
    }

  reparse:
    choice = input[0];
    // repeat last command
    if(choice == '\n' && last_input[0] != 0)
    {
      strcpy(input, last_input);
      goto reparse;
    }
    else 
    {
      // save current input 
      strcpy(last_input, input);
    }

    if(choice == 'q')
    {
      break;
    }
    else if(choice == 'a' || choice == 'm' || choice == 'p' || choice == 'd')
    {
      char *arg = NULL;
      size_t offset = 0;
      size_t range = 0;
      int advice = 0;
      volatile uint8_t tmp = 0;
      (void) tmp;

      // parse arguments (common)
      strtok(input, " ");
      
      arg = strtok(NULL, " ");
      if(arg == NULL) {
        printf("Invalid syntax!\n");
        continue;
      }
      offset = strtoul(arg, NULL, 16) * PAGE_SIZE;
      if(offset > file_mapping.size_) {
        printf("Out of range!\n");
        continue;
      }

      arg = strtok(NULL, " ");
      if(arg == NULL) {
        printf("Invalid syntax!\n");
        continue;
      }
      range = strtoul(arg, NULL, 16) * PAGE_SIZE;
      if(range == 0) {
        range = file_mapping.size_pages_ * PAGE_SIZE;
      }
      if((offset + range) > (file_mapping.size_pages_ * PAGE_SIZE)) {
        printf("Out of range!\n");
        continue;
      }
      
      // additonal argument for madvise command
      if(choice == 'm') {
        arg = strtok(NULL, " ");
        if(arg == NULL) {
          printf("Invalid syntax!\n");
          continue;
        }
        advice = strtol(arg, NULL, 16);
      }

      // execute commands
      if(choice == 'a') {
        // access pages
        for(size_t current = offset; current < (offset + range); current += PAGE_SIZE)
        {
          tmp = *((uint8_t *) file_mapping.addr_ + current);
        }
      }
      else if(choice == 'm') {
        //printf("%lx %lx %d\n", offset, range, advice);
        if(posix_fadvise(file_mapping.fd_, offset, range, advice) != 0) {
          printf("posix_fadvise failed: %s!", strerror(errno));
        }
        if(madvise((uint8_t *) file_mapping.addr_ + offset, range, advice) != 0) {
          printf("madvise failed: %s!", strerror(errno));
        }
      }
      else if(choice == 'p' || choice == 'd') {
        if(active_pc_state_fn(file_mapping.fd_, file_mapping.addr_, offset, range, pages_status) != 0)
        {
          printf("pc_state_fn failed: %s!", strerror(errno));
          continue;
        }
        printPcState(pages_status, (choice == 'd') ? last_pages_status : NULL, range / PAGE_SIZE, offset);
        // save last page status
        memcpy(last_pages_status, pages_status, file_mapping.size_pages_);
      }
    }
    else if(choice == 'c') {
      void *arg = NULL;
      int selection = 0;

      // parse arguments
      strtok(input, " ");
      
      arg = strtok(NULL, " ");
      if(arg == NULL) {
        printf("Invalid syntax!\n");
        continue;
      }
      selection = atoi(arg);
      if(selection > sizeof(PC_STATE_FNS) / sizeof(PcStateFn)) {
        printf("Out of range!\n");
        continue;
      }

      active_pc_state_fn = PC_STATE_FNS[selection];
    }
    else if(choice == 's') {
      char *arg = NULL;
      size_t offset = 0;

      // check if pageflags are available
      if(!pageFlagsFdValid(&pageflags_fd)) {
        printf("Page flags not available\n");
        continue;
      }

      // parse arguments (common)
      strtok(input, " ");
      
      arg = strtok(NULL, " ");
      if(arg == NULL) {
        printf("Invalid syntax!\n");
        continue;
      }
      offset = strtoul(arg, NULL, 16) * PAGE_SIZE;
      if(offset > file_mapping.size_) {
        printf("Out of range!\n");
        continue;
      }


      // print interesting page flags
      if(getKPageFlagsEntryVpn(&pageflags_fd, &page_flags, ((size_t) file_mapping.addr_ + offset) / PAGE_SIZE) != 0)
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
  }


  goto cleanup;
error:

  ret = -1;

cleanup:

  if(pages_status != NULL)
  {
    free(pages_status);
  }
  if(last_pages_status != NULL) {
    free(last_pages_status);
  }
  closeFileMapping(&file_mapping);
  closePageFlagsFd(&pageflags_fd);
  return ret;
}


void usageError(char *program_name)
{
  printf("Usage: %s <file to analyze>\n", program_name);
}


int doPcStateMincore(int fd, void *addr, size_t offset, size_t length, unsigned char *vec) {
  return mincore((uint8_t *) addr + offset, length, vec);
}

int doPcStatePreadV2(int fd, void *addr, size_t offset, size_t length, unsigned char *vec) {
  int ret = 0;
  volatile uint8_t tmp = 0;
  (void) tmp;
  struct iovec io_range = {0};
  io_range.iov_base = (void *) &tmp;
  io_range.iov_len = sizeof(tmp);
  
  for(size_t current_ofs = offset; current_ofs < (offset + length); current_ofs += PAGE_SIZE, vec++) {
    ret = preadv2(fd, &io_range, 1, current_ofs, RWF_NOWAIT);
    if(ret == -1)
    {
      if(errno == EAGAIN)
      {
       *vec = 0;
      }
      else 
      {
        return ret;
      }
    }
    else {
      *vec = 1;
    }
  }

  return 0;
}

int doPcStateAccess(int fd, void *addr, size_t offset, size_t length, unsigned char *vec) {
  uint8_t *current_addr = (uint8_t *) addr + offset;
  uint8_t *end_addr = current_addr + length;
  volatile uint8_t tmp = 0;
  (void) tmp;
  uint64_t start_cycle = 0, end_cycle = 0;

  for(; current_addr < end_addr; current_addr += PAGE_SIZE, vec++) {
    sched_yield();
    TSC_BENCH_START(start_cycle);
    tmp = *current_addr;
    TSC_BENCH_STOP(end_cycle);
    uint64_t access_time = tsc_bench_get_runtime_ns(start_cycle, end_cycle);
    *vec = access_time < DISK_ACCESS_THRESHOLD_NS;
  }
  
  return 0;
}


void printPcState(unsigned char *pages_status, unsigned char *last_pages_status, size_t range, size_t print_start_addr) {
  for(size_t page = 0; page < range; page++)
  {
    if(page % (CLUSTER_PAGES * CLUSTERS_PER_LINE) == 0) 
    {
      printf("\n0x%08lx:\t", print_start_addr + page * PAGE_SIZE);
    }
    else if(page % CLUSTER_PAGES == 0) 
    {
      printf("\t");
    }

    if(last_pages_status == NULL)
    { 
      printf("%d", pages_status[page] & 1);
    }
    else 
    {
      printf("%d", (pages_status[page] & 1) ^ (last_pages_status[page] & 1));
    }
  }
  printf("\n");
}