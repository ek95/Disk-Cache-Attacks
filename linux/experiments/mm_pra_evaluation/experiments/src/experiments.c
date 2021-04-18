#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include "filemap.h"
#include "pageflags.h"


#define ARG_COUNT 2
#define MODE_ARG 1

#define EVICTION_FILENAME "eviction.ram"

#define TEST_FILE_PATH "test.so"
#define TEST_FILE_SIZE (2*1024*1024ULL)
#define TEST_FILE_TARGET_PAGE (0xAA)
#define TEST_FILE_VICTIM_PAGE (0x10)

#define READ_CLEAN_FILE_PAGE_USER_1 0
#define READ_CLEAN_FILE_PAGE_USER_2 1
#define READ_CLEAN_FILE_PAGE_USER_3 2
#define READ_MAPPED_EXEC_CLEAN_FILE_PAGE_USER_1 3
#define ACCESS_MAPPED_CLEAN_FILE_PAGE_USER_1 4
#define ACCESS_MAPPED_CLEAN_FILE_PAGE_USER_2 5
#define ACCESS_MAPPED_EXEC_CLEAN_FILE_PAGE_USER_1 6
#define READ_ACCESS_MAPPED_CLEAN_FILE_PAGE_USER_1 7
#define READ_CLEAN_FILE_PAGE_USER_VMSCAN 8
#define MIN_MODE READ_CLEAN_FILE_PAGE_USER_1
#define MAX_MODE READ_CLEAN_FILE_PAGE_USER_VMSCAN

#define WAIT_TIME_NS (100*1000*1000ULL)

#define DEBUG

#ifdef DEBUG
#define DEBUG_PRINT(x) printf x
#else
#define DEBUG_PRINT(x) \
    do {               \
    } while(0)
#endif


const char *experiment_strings[] = 
  {
    "read clean file page once, and print pageflags",
    "read clean file page twice, and print pageflags",
    "read clean file page three times, and print pageflags",
    "read clean file page which is mapped executable once, and print pageflags",
    "access regulary mapped clean file page once, trigger vmscan and print pageflags",
    "access regulary mapped clean file page twice, trigger vmscan and print pageflags",
    "access executable mapped clean file page once, trigger vmscan and print pageflags",
    "read + access regulary mapped clean file page once, trigger vmscan and print pageflags",
    "read regulary mapped clean file page once, trigger vmscan and print pageflags"
  };
size_t PAGE_SIZE = 0;


void printPageflags(PageFlagsFd *pageflags_fd, void *addr);
void waitUntilKswapd0Sleeps(); 
void waitUntilVictimPageEvicted(FileMapping *eviction_file_mapping, void *victim_addr);
void usageError(char *program_name);


int main(int argc, char *argv[])
{
  int ret = 0;
  int mode = 0;
  FileMapping test_file_mapping;
  FileMapping eviction_file_mapping;
  PageFlagsFd pageflags_fd;
  struct sysinfo system_info;
  volatile uint8_t tmp = 0;
  uint8_t *target_addr = NULL;
  uint8_t *victim_addr = NULL;
  unsigned char pc_target_status = 0;
  unsigned char pc_victim_status = 0;
  (void) tmp;

  initFileMapping(&test_file_mapping);
  initFileMapping(&eviction_file_mapping);


  if(argc != ARG_COUNT)
  {
    usageError(argv[0]);
    goto error;
  }
    // parse mode and check if valid
  mode = atoi(argv[MODE_ARG]);
  if(mode < MIN_MODE || mode > MAX_MODE) {
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
  // get system info
  if(sysinfo(&system_info) != 0)
  {
    printf("Error (%s) at sysinfo...\n", strerror(errno));
    goto error;
  }


  // open page flags
  if(openPageFlagsFd(&pageflags_fd) != 0)
  {
    printf("Error (%s) at openPageFlags\n", strerror(errno));
    goto error;
  }

  // create + mmap test file    
  if(createRandomFile(TEST_FILE_PATH, TEST_FILE_SIZE) != 0)
  {
    printf("Error (%s) at createRandomFile\n", strerror(errno));
     goto error;
  }
  if(mode == READ_MAPPED_EXEC_CLEAN_FILE_PAGE_USER_1 || mode == ACCESS_MAPPED_EXEC_CLEAN_FILE_PAGE_USER_1) {
    // map test file executable
    if(mapFile(&test_file_mapping, TEST_FILE_PATH, O_RDONLY, PROT_READ | PROT_EXEC, MAP_PRIVATE) != 0)
    {
        printf("Error (%s) at mapFile for: %s ...\n", strerror(errno), TEST_FILE_PATH);
        goto error;
    }  
  }
  else {
    // map test file non-executable
    if(mapFile(&test_file_mapping, TEST_FILE_PATH, O_RDONLY, PROT_READ, MAP_PRIVATE) != 0)
    {
        printf("Error (%s) at mapFile for: %s ...\n", strerror(errno), TEST_FILE_PATH);
        goto error;
    }  
  }
    // calculate address
  target_addr = (uint8_t *)test_file_mapping.addr_ + TEST_FILE_TARGET_PAGE * PAGE_SIZE;
  victim_addr = (uint8_t *)test_file_mapping.addr_ + TEST_FILE_VICTIM_PAGE * PAGE_SIZE;
  // flush target + victim page
  do {
    posix_fadvise(test_file_mapping.fd_, TEST_FILE_TARGET_PAGE * PAGE_SIZE, PAGE_SIZE, POSIX_FADV_DONTNEED);
    posix_fadvise(test_file_mapping.fd_, TEST_FILE_VICTIM_PAGE * PAGE_SIZE, PAGE_SIZE, POSIX_FADV_DONTNEED);
    mincore(target_addr, PAGE_SIZE, &pc_target_status);
    mincore(victim_addr, PAGE_SIZE, &pc_victim_status);
  } while((pc_target_status & 1) || (pc_victim_status & 1));
  // advise no readahead
  posix_fadvise(test_file_mapping.fd_, 0, 0, POSIX_FADV_RANDOM);



  // need eviction file for every tests except these tests
  if(mode != READ_CLEAN_FILE_PAGE_USER_1 && mode != READ_CLEAN_FILE_PAGE_USER_2 && mode != READ_CLEAN_FILE_PAGE_USER_3 &&
     mode != READ_MAPPED_EXEC_CLEAN_FILE_PAGE_USER_1) {
    // create eviction file if not exists already
    if(createRandomFile(EVICTION_FILENAME, system_info.totalram) != 0)
    {
        printf("Error(%s) at createRandomFile...\n", strerror(errno));
        goto error;
    }

    // map eviction memory
    if(mapFile(&eviction_file_mapping, EVICTION_FILENAME, O_RDONLY, PROT_READ | PROT_EXEC, MAP_PRIVATE) != 0)
    {
        printf("Error (%s) at mapFile for: %s ...\n", strerror(errno), EVICTION_FILENAME);
        goto error;
    }  
  }


  // experiments
  printf("Running experiment %s:\n", experiment_strings[mode]);
  if(mode == READ_CLEAN_FILE_PAGE_USER_1 || mode == READ_MAPPED_EXEC_CLEAN_FILE_PAGE_USER_1)
  {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    // first read access 
    if(pread(test_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(test_file_mapping.fd_, TEST_FILE_VICTIM_PAGE * PAGE_SIZE, PAGE_SIZE, POSIX_FADV_DONTNEED);
  }
  else if(mode == READ_CLEAN_FILE_PAGE_USER_2)
  {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    // first read access 
    if(pread(test_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    // second read access
    if(pread(test_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(test_file_mapping.fd_, TEST_FILE_VICTIM_PAGE * PAGE_SIZE, PAGE_SIZE, POSIX_FADV_DONTNEED);
  }
  else if(mode == READ_CLEAN_FILE_PAGE_USER_3)
  {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    // first read access 
    if(pread(test_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    // second read access
    if(pread(test_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    // third read access
    if(pread(test_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(test_file_mapping.fd_, TEST_FILE_VICTIM_PAGE * PAGE_SIZE, PAGE_SIZE, POSIX_FADV_DONTNEED);
  }
  else if(mode == ACCESS_MAPPED_CLEAN_FILE_PAGE_USER_1)
  {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    // first access
    tmp = *target_addr;
    // victim page
    if(pread(test_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_VICTIM_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    waitUntilVictimPageEvicted(&eviction_file_mapping, victim_addr);
  }
  else if(mode == ACCESS_MAPPED_CLEAN_FILE_PAGE_USER_2)
  {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    // first access
    tmp = *target_addr;
    // victim page
    if(pread(test_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_VICTIM_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    waitUntilVictimPageEvicted(&eviction_file_mapping, victim_addr);
    // ensure victim page is evicted 
    posix_fadvise(test_file_mapping.fd_, TEST_FILE_VICTIM_PAGE * PAGE_SIZE, PAGE_SIZE, POSIX_FADV_DONTNEED);
    // second access
    tmp = *target_addr;
    // victim page
    if(pread(test_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_VICTIM_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    waitUntilVictimPageEvicted(&eviction_file_mapping, victim_addr);
  }
  else if(mode == ACCESS_MAPPED_EXEC_CLEAN_FILE_PAGE_USER_1)
  {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    // first access
    tmp = *target_addr;
    // victim page
    if(pread(test_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_VICTIM_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    waitUntilVictimPageEvicted(&eviction_file_mapping, victim_addr);
  }
  else if(mode == READ_ACCESS_MAPPED_CLEAN_FILE_PAGE_USER_1) 
  {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    // first read access 
    if(pread(test_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    // second access
    tmp = *target_addr;
    // victim page
    if(pread(test_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_VICTIM_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    waitUntilVictimPageEvicted(&eviction_file_mapping, victim_addr);
  }
  else if(mode == READ_CLEAN_FILE_PAGE_USER_VMSCAN) 
  {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    // first read access 
    if(pread(test_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    // victim page
    if(pread(test_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_VICTIM_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    waitUntilVictimPageEvicted(&eviction_file_mapping, victim_addr);
  }

  waitUntilKswapd0Sleeps();
  // for all read modes we must create the page table to query the state 
  if(mode == READ_CLEAN_FILE_PAGE_USER_1 || mode == READ_CLEAN_FILE_PAGE_USER_2 || mode == READ_CLEAN_FILE_PAGE_USER_3 ||
     mode == READ_MAPPED_EXEC_CLEAN_FILE_PAGE_USER_1)
  {
    DEBUG_PRINT(("Ensuring page table entry exists.\n"));
    tmp = *((uint8_t *) target_addr);
  }
  // print pageflags
  printPageflags(&pageflags_fd, target_addr);


  goto cleanup;
error:

  ret = -1;

cleanup:

  closeFileMapping(&test_file_mapping);
  closeFileMapping(&eviction_file_mapping);
  return ret;
}


// NOTE that this accesses the page to create the page table entry
// in order to not influence the flags ensure kswapd0 is not running
// when this is called, e.g. all zones have enough free memory
void printPageflags(PageFlagsFd *pageflags_fd, void *addr) {
  volatile uint8_t tmp = 0;
  KPageFlagsEntry page_flags;
  (void) tmp;

  if(getKPageFlagsEntryVpn(pageflags_fd, &page_flags, (size_t) addr / PAGE_SIZE) != 0)
  {
    printf("Error (%s) at getKPageFlagsEntryVpn, continuing\n", strerror(errno));
    return;
  }

  printf("Referenced: %u\n", page_flags.referenced);
  printf("Lru: %u\n", page_flags.lru);
  printf("Active: %u\n", page_flags.active);
  printf("Mmap: %u\n", page_flags.mmap);
  printf("Anon: %u\n", page_flags.anon);
  printf("Idle: %u\n", page_flags.idle);
}


void waitUntilKswapd0Sleeps() 
{
  char line_buffer[255];
  FILE *process_pipe;
  struct timespec wait_time = {
    .tv_sec = 0,
    .tv_nsec = WAIT_TIME_NS
  };

  // wait till kswapd0 is sleeping
  while(1) 
  { 
    process_pipe = popen("ps -o stat= -C kswapd0", "r");
    if(process_pipe == NULL) 
    {
      printf("Error (%s) at popen\n", strerror(errno));
      printf("Resulting flags might not be trusted!\n");
      break;
    }

    if(fgets(line_buffer, sizeof(line_buffer), process_pipe) == NULL) 
    {
      printf("Error (%s) at fgets\n", strerror(errno));
      return;
    }
    if(strlen(line_buffer) == 2 && line_buffer[0] == 'S') 
    {
      break;
    }

    pclose(process_pipe);
    nanosleep(&wait_time, NULL);
  }

  if(process_pipe != NULL) 
  {
    pclose(process_pipe);
  }
}


void waitUntilVictimPageEvicted(FileMapping *eviction_file_mapping, void *victim_addr) {
  volatile uint8_t tmp = 0;
  unsigned char pc_status;
  (void) tmp;

  while(1)
  {
    for(size_t p = 0; p < eviction_file_mapping->size_pages_; p++) 
    {
      tmp = *((uint8_t *) eviction_file_mapping->addr_ + p * PAGE_SIZE);
      // stop as soon as victim page left memory
      mincore(victim_addr, PAGE_SIZE, &pc_status);
      if(!(pc_status & 1)) 
      {
        return;
      }
    }
  }
}


void usageError(char *program_name)
{
  printf("Usage: %s [mode].\n", program_name);
  for(int i = MIN_MODE; i <= MAX_MODE; i++)
  {
    printf("%d: \t%s\n", i, experiment_strings[i]);
  }
}
