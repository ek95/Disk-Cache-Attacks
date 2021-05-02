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
#include <pthread.h>
#include "filemap.h"
#include "pageflags.h"


#define ARG_COUNT 2
#define MODE_ARG 1

#define EVICTION_FILENAME "eviction.ram"

#define TEST_EXEC_FILE_PATH "test.so"
#define TEST_READ_FILE_PATH "test.dat"
#define TEST_WRITE_FILE_PATH "test-wr.dat"
#define TEST_FILE_SIZE (2*1024*1024ULL)
// last page
#define TEST_FILE_TARGET_PAGE (0x1ff)
// outside of first page-in block
#define TEST_FILE_VICTIM_PAGE (0x20)
#define TEST_FILE_VICTIM_PAGE2 (0x100)

#define READ_CLEAN_FILE_PAGE_USER_1 0
#define READ_CLEAN_FILE_PAGE_USER_2 1
#define READ_CLEAN_FILE_PAGE_USER_3 2
#define WRITE_FILE_PAGE_USER_3 3
#define READ_MAPPED_EXEC_CLEAN_FILE_PAGE_USER_1 4
#define ACCESS_MAPPED_CLEAN_FILE_PAGE_USER_1 5
#define ACCESS_MAPPED_CLEAN_FILE_PAGE_USER_2 6
#define ACCESS_MAPPED_FILE_PAGE_USER_1 7
#define ACCESS_MAPPED_FILE_PAGE_USER_2 8
#define ACCESS_MAPPED_EXEC_CLEAN_FILE_PAGE_USER_1 9
#define EXT_READ_ACCESS_MAPPED_EXEC_CLEAN_FILE_PAGE_USER_2 10
#define READ_ACCESS_MAPPED_CLEAN_FILE_PAGE_USER_1 11
#define EXT_READ_ACCESS_MAPPED_CLEAN_FILE_PAGE_USER_3 12
#define EXT_READ_ACCESS_MAPPED_CLEAN_FILE_PAGE_USER_1 13
#define WORKING_SET_READ_REFAULT_FILE_PAGE_USER 14
#define WORKING_SET_ACCESS_REFAULT_FILE_PAGE_USER 15
#define WORKING_SET_WRITE_REFAULT_FILE_PAGE_USER 16
#define DIRTY_FILE_PAGE_USER_RECLAIMING 17
#define MIN_MODE READ_CLEAN_FILE_PAGE_USER_1
#define MAX_MODE DIRTY_FILE_PAGE_USER_RECLAIMING

#define WAIT_TIME_NS (100*1000*1000ULL)

#define DEBUG

#ifdef DEBUG
#define DEBUG_PRINT(x) printf x
#else
#define DEBUG_PRINT(x) \
    do {               \
    } while(0)
#endif


struct PageflagSamplerArg {
  PageFlagsFd *pageflags_fd_;
  pthread_t thread_;
  uint8_t run_;
  uint8_t running_;
  size_t sample_period_ns_;
  size_t target_pfn_;
};


const char *experiment_strings[] = 
{
    "read read-only mapped clean file page once, and print pageflags",
    "read read-only mapped clean file page twice, and print pageflags",
    "read read-only mapped clean file page three times, and print pageflags",
    "write read-write mapped file page three times", 
    "read executable mapped clean file page once, and print pageflags",
    "access read-only mapped clean file page once, trigger vmscan and print pageflags",
    "access read-only mapped clean file page twice, trigger vmscan and print pageflags",
    "access (write) read-write mapped file page once, trigger vmscan and print pageflags",
    "access (write) read-write mapped file page twice, trigger vmscan and print pageflags",
    "access executable mapped clean file page once, trigger vmscan and print pageflags",
    "read (2x) + access executable mapped clean file page, read (2x) + access a read-only mapped clean file page, evict read-only page and print pageflags",
    "read + access read-only mapped clean file page once, trigger vmscan and print pageflags",
    "read (3x) + access a read-only mapped clean file page, read (2x) executable mapped clean file page, evict executable page and print pageflags",
    "read (1x) + access a read-only mapped clean file page, read (2x) executable mapped clean file page, evict executable page and print pageflags",
    "workingset refault (read)",
    "workingset refault (access)",
    "workingset refault (write)",
    "dirty page reclaiming"
};


size_t PAGE_SIZE = 0;


void printPageflags(KPageFlagsEntry *page_flags);
void samplePageflags(PageFlagsFd *pageflags_fd, void *addr);
int startPageflagSampler(struct PageflagSamplerArg *sampler); 
int stopPageflagSampler(struct PageflagSamplerArg *sampler);
void *pageflagSampler(void *arg);
void waitUntilKswapd0Sleeps(); 
void evictPage(FileMapping *eviction_file_mapping, void *victim_addr);
void flushExclusivePage(FileMapping *mapping, size_t page);
void usageError(char *program_name);


int main(int argc, char *argv[])
{
  int ret = 0;
  int mode = 0;
  FileMapping test_read_file_mapping, test_exec_file_mapping, test_write_file_mapping;
  FileMapping eviction_file_mapping;
  PageFlagsFd pageflags_fd;
  struct PageflagSamplerArg sampler_arg = {
    .pageflags_fd_ = &pageflags_fd, 
    .sample_period_ns_ = 0
  };
  struct sysinfo system_info;
  volatile uint8_t tmp = 0;
  uint8_t *exec_target_addr = NULL, *read_target_addr = NULL, *write_target_addr = NULL;
  uint8_t *exec_victim_addr = NULL, *read_victim_addr = NULL, *read_victim2_addr = NULL, *write_victim_addr = NULL;
  unsigned char pc_status = 0;
  (void) tmp;


  initFileMapping(&test_read_file_mapping);
  initFileMapping(&test_exec_file_mapping);
  initFileMapping(&test_write_file_mapping);
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

  // create test file    
  if(createRandomFile(TEST_READ_FILE_PATH, TEST_FILE_SIZE) != 0)
  {
    printf("Error (%s) at createRandomFile\n", strerror(errno));
    goto error;
  }
  // create test file    
  if(createRandomFile(TEST_EXEC_FILE_PATH, TEST_FILE_SIZE) != 0)
  {
    printf("Error (%s) at createRandomFile\n", strerror(errno));
    goto error;
  }
  // create test file    
  if(createRandomFile(TEST_WRITE_FILE_PATH, TEST_FILE_SIZE) != 0)
  {
    printf("Error (%s) at createRandomFile\n", strerror(errno));
    goto error;
  }


  // map test file non-executable
  if(mapFile(&test_read_file_mapping, TEST_READ_FILE_PATH, O_RDONLY, PROT_READ, MAP_SHARED) != 0)
  {
      printf("Error (%s) at mapFile for: %s ...\n", strerror(errno), TEST_READ_FILE_PATH);
      goto error;
  }  
  // map test file executable
  if(mapFile(&test_exec_file_mapping, TEST_EXEC_FILE_PATH, O_RDONLY, PROT_READ | PROT_EXEC, MAP_SHARED) != 0)
  {
        printf("Error (%s) at mapFile for: %s ...\n", strerror(errno), TEST_EXEC_FILE_PATH);
        goto error;
  } 
  // map test file executable
  if(mapFile(&test_write_file_mapping, TEST_WRITE_FILE_PATH, O_RDWR, PROT_READ | PROT_WRITE, MAP_SHARED) != 0)
  {
        printf("Error (%s) at mapFile for: %s ...\n", strerror(errno), TEST_WRITE_FILE_PATH);
        goto error;
  }   

  
  // calculate address
  read_target_addr = (uint8_t *)test_read_file_mapping.addr_ + TEST_FILE_TARGET_PAGE * PAGE_SIZE;
  read_victim_addr = (uint8_t *)test_read_file_mapping.addr_ + TEST_FILE_VICTIM_PAGE * PAGE_SIZE;
  read_victim2_addr = (uint8_t *)test_read_file_mapping.addr_ + TEST_FILE_VICTIM_PAGE2 * PAGE_SIZE;

  exec_target_addr = (uint8_t *)test_exec_file_mapping.addr_ + TEST_FILE_TARGET_PAGE * PAGE_SIZE;
  exec_victim_addr = (uint8_t *)test_exec_file_mapping.addr_ + TEST_FILE_VICTIM_PAGE * PAGE_SIZE;

  write_target_addr = (uint8_t *)test_write_file_mapping.addr_ + TEST_FILE_TARGET_PAGE * PAGE_SIZE;
  write_victim_addr = (uint8_t *)test_write_file_mapping.addr_ + TEST_FILE_VICTIM_PAGE * PAGE_SIZE;


  // ensure target and victim pages are flushed
  flushExclusivePage(&test_read_file_mapping, TEST_FILE_TARGET_PAGE);
  flushExclusivePage(&test_read_file_mapping, TEST_FILE_VICTIM_PAGE);

  flushExclusivePage(&test_exec_file_mapping, TEST_FILE_TARGET_PAGE);
  flushExclusivePage(&test_exec_file_mapping, TEST_FILE_VICTIM_PAGE);

  flushExclusivePage(&test_write_file_mapping, TEST_FILE_TARGET_PAGE);
  flushExclusivePage(&test_write_file_mapping, TEST_FILE_VICTIM_PAGE);

  // advise no readahead
  posix_fadvise(test_read_file_mapping.fd_, 0, 0, POSIX_FADV_RANDOM);
  posix_fadvise(test_exec_file_mapping.fd_, 0, 0, POSIX_FADV_RANDOM);
  posix_fadvise(test_write_file_mapping.fd_, 0, 0, POSIX_FADV_RANDOM);


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
  
  // cycle one page through the whole LRU, avoids effects from shadow entries in the later experiments
  // run until starts to evict form itsself
  tmp = *((uint8_t *) eviction_file_mapping.addr_);
  evictPage(&eviction_file_mapping, eviction_file_mapping.addr_);
  posix_fadvise(eviction_file_mapping.fd_, 0, 0, POSIX_FADV_DONTNEED);  
  posix_fadvise(eviction_file_mapping.fd_, 0, 0, POSIX_FADV_RANDOM); 


  // experiments
  printf("Running experiment %s:\n", experiment_strings[mode]);
  if(mode == READ_CLEAN_FILE_PAGE_USER_1)
  {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    // first read access 
    if(pread(test_read_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(eviction_file_mapping.fd_, 0, PAGE_SIZE, POSIX_FADV_DONTNEED);
  }
  else if(mode == READ_CLEAN_FILE_PAGE_USER_2)
  {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    // two read accesses
    if(pread(test_read_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1 ||
       pread(test_read_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(eviction_file_mapping.fd_, 0, PAGE_SIZE, POSIX_FADV_DONTNEED);
  }
  else if(mode == READ_CLEAN_FILE_PAGE_USER_3)
  {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    // three read accesses
    if(pread(test_read_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1 ||
       pread(test_read_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1 ||
       pread(test_read_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(eviction_file_mapping.fd_, 0, PAGE_SIZE, POSIX_FADV_DONTNEED);
  }
  else if(mode == WRITE_FILE_PAGE_USER_3)
  {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    // three read accesses
    tmp = 0xff;
    if(pwrite(test_write_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1 ||
       pwrite(test_write_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1 ||
       pwrite(test_write_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(eviction_file_mapping.fd_, 0, PAGE_SIZE, POSIX_FADV_DONTNEED);
  }
  else if(mode == READ_MAPPED_EXEC_CLEAN_FILE_PAGE_USER_1)
  {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    // first read access 
    if(pread(test_exec_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(eviction_file_mapping.fd_, 0, PAGE_SIZE, POSIX_FADV_DONTNEED);
  }
  else if(mode == ACCESS_MAPPED_CLEAN_FILE_PAGE_USER_1)
  {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    // first access
    tmp = *read_target_addr;
    
    // victim page
    if(pread(test_read_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_VICTIM_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    evictPage(&eviction_file_mapping, read_victim_addr);
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(eviction_file_mapping.fd_, 0, PAGE_SIZE, POSIX_FADV_DONTNEED);
  }
  else if(mode == ACCESS_MAPPED_CLEAN_FILE_PAGE_USER_2)
  {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    // first access
    tmp = *read_target_addr;
    // victim page
    if(pread(test_read_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_VICTIM_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    evictPage(&eviction_file_mapping, read_victim_addr);
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(eviction_file_mapping.fd_, 0, PAGE_SIZE, POSIX_FADV_DONTNEED);

    // second access
    tmp = *read_target_addr;
    // victim page
    if(pread(test_read_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_VICTIM_PAGE2 * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    evictPage(&eviction_file_mapping, read_victim2_addr);
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(eviction_file_mapping.fd_, 0, PAGE_SIZE, POSIX_FADV_DONTNEED);
  }
  else if(mode == ACCESS_MAPPED_FILE_PAGE_USER_1)
  {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    // first access
    *write_target_addr = 0xaa;
    // victim page
    if(pread(test_read_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_VICTIM_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    evictPage(&eviction_file_mapping, read_victim_addr);
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(eviction_file_mapping.fd_, 0, PAGE_SIZE, POSIX_FADV_DONTNEED);
  }
  else if(mode == ACCESS_MAPPED_FILE_PAGE_USER_2)
  {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    // first access
    *write_target_addr = 0xaa;
    // victim page
    if(pread(test_read_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_VICTIM_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    evictPage(&eviction_file_mapping, read_victim_addr);
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(eviction_file_mapping.fd_, 0, PAGE_SIZE, POSIX_FADV_DONTNEED);

    // second access
    *write_target_addr = 0xbb;
    // victim page
    if(pread(test_read_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_VICTIM_PAGE2 * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    evictPage(&eviction_file_mapping, read_victim2_addr);
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(eviction_file_mapping.fd_, 0, PAGE_SIZE, POSIX_FADV_DONTNEED);
  }
  else if(mode == ACCESS_MAPPED_EXEC_CLEAN_FILE_PAGE_USER_1)
  {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    // first access
    tmp = *exec_target_addr;
    // victim page
    if(pread(test_read_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_VICTIM_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    evictPage(&eviction_file_mapping, read_victim_addr);
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(eviction_file_mapping.fd_, 0, PAGE_SIZE, POSIX_FADV_DONTNEED);
  }
  else if(mode == EXT_READ_ACCESS_MAPPED_EXEC_CLEAN_FILE_PAGE_USER_2) 
  {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    // two reads of executably mapped target page
    if(pread(test_exec_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1 ||
       pread(test_exec_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(eviction_file_mapping.fd_, 0, PAGE_SIZE, POSIX_FADV_DONTNEED);
    // access executably mapped target page
    tmp = *exec_target_addr;

    // two reads of read-only target mapped page
    if(pread(test_read_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1 ||
       pread(test_read_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(eviction_file_mapping.fd_, 0, PAGE_SIZE, POSIX_FADV_DONTNEED);
    // access to read-only mapped page
    tmp = *read_target_addr;

    // wait till readable target is evicted
    // executable target should still be in memory even though "older" as it got a second run through the active list
    evictPage(&eviction_file_mapping, read_target_addr);
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(eviction_file_mapping.fd_, 0, PAGE_SIZE, POSIX_FADV_DONTNEED);
  }
  else if(mode == READ_ACCESS_MAPPED_CLEAN_FILE_PAGE_USER_1) 
  {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    // read access 
    if(pread(test_read_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    // mapping access
    tmp = *read_target_addr;

    // victim page
    if(pread(test_read_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_VICTIM_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    evictPage(&eviction_file_mapping, read_victim_addr);
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(eviction_file_mapping.fd_, 0, PAGE_SIZE, POSIX_FADV_DONTNEED);
  }
  else if(mode == EXT_READ_ACCESS_MAPPED_CLEAN_FILE_PAGE_USER_3) 
  {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    // three reads of read-only mapped target page
    if(pread(test_read_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1 ||
       pread(test_read_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1 ||
       pread(test_read_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(eviction_file_mapping.fd_, 0, PAGE_SIZE, POSIX_FADV_DONTNEED);
    // access to read-only mapped target page
    tmp = *read_target_addr;

    // two reads of executable mapped target page
    if(pread(test_exec_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1 ||
       pread(test_exec_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(eviction_file_mapping.fd_, 0, PAGE_SIZE, POSIX_FADV_DONTNEED);

    // wait till executable target is evicted
    // readable target should not be in memory anymore even though it had three reads and was referenced via mapping
    evictPage(&eviction_file_mapping, exec_target_addr);
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(eviction_file_mapping.fd_, 0, PAGE_SIZE, POSIX_FADV_DONTNEED);
  }
  else if(mode == EXT_READ_ACCESS_MAPPED_CLEAN_FILE_PAGE_USER_1) 
  {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    // one read of read-only mapped target page
    if(pread(test_read_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(eviction_file_mapping.fd_, 0, PAGE_SIZE, POSIX_FADV_DONTNEED);
    // access to read-only mapped target page
    tmp = *read_target_addr;

    // two reads of executable target
    if(pread(test_exec_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1 ||
       pread(test_exec_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(eviction_file_mapping.fd_, 0, PAGE_SIZE, POSIX_FADV_DONTNEED);

    // wait till executable target is evicted
    // readable target should still be in memory -> compare with previous case
    evictPage(&eviction_file_mapping, exec_target_addr);
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(eviction_file_mapping.fd_, 0, PAGE_SIZE, POSIX_FADV_DONTNEED);
  }
  else if(mode == WORKING_SET_READ_REFAULT_FILE_PAGE_USER ||
    mode == WORKING_SET_ACCESS_REFAULT_FILE_PAGE_USER) {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    // one read of read-only mapped target page
    if(pread(test_read_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }

    // wait till read-only target is evicted
    evictPage(&eviction_file_mapping, read_target_addr);
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(eviction_file_mapping.fd_, 0, PAGE_SIZE, POSIX_FADV_DONTNEED);
    // wait until kswapd0 sleeps again
    waitUntilKswapd0Sleeps();

    // refault
    if(mode == WORKING_SET_READ_REFAULT_FILE_PAGE_USER) {
      if(pread(test_read_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1)
      {
        printf("Error (%s) at pread\n", strerror(errno));
        goto error;
      }
    }
    else {
      tmp = *read_target_addr;
    }
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(eviction_file_mapping.fd_, 0, PAGE_SIZE, POSIX_FADV_DONTNEED);
  }
  else if(mode == WORKING_SET_WRITE_REFAULT_FILE_PAGE_USER) {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    // one write to read-write mapped target page
    tmp = 0xaa;
    if(pwrite(test_write_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }

    // wait till read-only target is evicted
    evictPage(&eviction_file_mapping, write_target_addr);
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(eviction_file_mapping.fd_, 0, PAGE_SIZE, POSIX_FADV_DONTNEED);
    // wait until kswapd0 sleeps again
    waitUntilKswapd0Sleeps();

    // refault
    tmp = 0xbb;
    if(pwrite(test_write_file_mapping.fd_, (void *) &tmp, 1, TEST_FILE_TARGET_PAGE * PAGE_SIZE) != 1)
    {
      printf("Error (%s) at pread\n", strerror(errno));
      goto error;
    }
    // trigger lru_add_drain() by calling posix_fadvice
    posix_fadvise(eviction_file_mapping.fd_, 0, PAGE_SIZE, POSIX_FADV_DONTNEED);
  }
  else if(mode == DIRTY_FILE_PAGE_USER_RECLAIMING) {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    PageMapEntry map_entry;
    *write_target_addr = 0xaa;
    
    // get pfn
    if(getPagemapEntryVpn(&pageflags_fd, &map_entry, (size_t) write_target_addr / PAGE_SIZE) != 0) {
      printf("Error (%s) at getPagemapEntryVpn\n", strerror(errno));
      goto error;
    }
    else if(!map_entry.present) {
      printf("Page not present!");
      goto error;
    }

    // track target pfn status
    sampler_arg.target_pfn_ = map_entry.present_swap.present_info.pfn;
    startPageflagSampler(&sampler_arg);
    // wait till target is evicted
    evictPage(&eviction_file_mapping, write_target_addr);
    stopPageflagSampler(&sampler_arg);
  }
  waitUntilKswapd0Sleeps();

  // ensure a page table entry exists for the target pages that are in the page
  // cache and print their page flags if so
  mincore(read_target_addr, PAGE_SIZE, &pc_status);
  if(pc_status & 1) {
    // does not influence page state as long as there is no memory pressure == vm scan 
    // ensured above with waiting for sleeping of kswapd
    DEBUG_PRINT(("Ensuring read-only target page pte exists.\n"));
    tmp = *((uint8_t *) read_target_addr);
    printf("Read-only target page flags:\n");
    samplePageflags(&pageflags_fd, read_target_addr);
  }
  mincore(exec_target_addr, PAGE_SIZE, &pc_status);
  if(pc_status & 1) {
    // does not influence page state as long as there is no memory pressure == vm scan 
    // ensured above with waiting for sleeping of kswapd
    DEBUG_PRINT(("Ensuring executable target page pte exists.\n"));
    tmp = *((uint8_t *) exec_target_addr);
    printf("Executable target page flags:\n");
    samplePageflags(&pageflags_fd, exec_target_addr);
  }
  mincore(write_target_addr, PAGE_SIZE, &pc_status);
  if(pc_status & 1) {
    // does not influence page state as long as there is no memory pressure == vm scan 
    // ensured above with waiting for sleeping of kswapd
    DEBUG_PRINT(("Ensuring writeable target page pte exists.\n"));
    tmp = *((uint8_t *) write_target_addr);
    printf("Writeable target page flags:\n");
    samplePageflags(&pageflags_fd, write_target_addr);
  }


  goto cleanup;
error:

  ret = -1;

cleanup:

  closeFileMapping(&test_exec_file_mapping);
  closeFileMapping(&test_read_file_mapping);
  closeFileMapping(&test_write_file_mapping);
  closeFileMapping(&eviction_file_mapping);

  return ret;
}


void printPageflags(KPageFlagsEntry *page_flags) {
  printf("Referenced: %u\n", page_flags->referenced);
  printf("Lru: %u\n", page_flags->lru);
  printf("Active: %u\n", page_flags->active);
  printf("Mmap: %u\n", page_flags->mmap);
  printf("Anon: %u\n", page_flags->anon);
  printf("Idle: %u\n", page_flags->idle);
  printf("Dirty: %u\n", page_flags->dirty);
  printf("Reclaim: %u\n", page_flags->reclaim);
  printf("Writeback: %u\n", page_flags->writeback);
  printf("\n");
}

// NOTE that this accesses the page to create the page table entry
// in order to not influence the flags ensure kswapd0 is not running
// when this is called, e.g. all zones have enough free memory
void samplePageflags(PageFlagsFd *pageflags_fd, void *addr) {
  volatile uint8_t tmp = 0;
  KPageFlagsEntry page_flags;
  (void) tmp;

  if(getKPageFlagsEntryVpn(pageflags_fd, &page_flags, (size_t) addr / PAGE_SIZE) != 0)
  {
    printf("Error (%s) at getKPageFlagsEntryVpn, continuing\n", strerror(errno));
    return;
  }

  printPageflags(&page_flags);
}

int startPageflagSampler(struct PageflagSamplerArg *sampler) {
  sampler->run_ = 1;
  sampler->running_ = 0;
  if(pthread_create(&sampler->thread_, NULL, pageflagSampler, sampler) != 0) {
    return -1;
  }
  // busy polling
  while(!__atomic_load_n(&sampler->running_, __ATOMIC_RELAXED));
  return 0;
}

int stopPageflagSampler(struct PageflagSamplerArg *sampler) {
  __atomic_store_n(&sampler->run_, 0, __ATOMIC_RELAXED);
  if(pthread_join(sampler->thread_, NULL) != 0) {
    return -1;
  }
  return 0;
}

void *pageflagSampler(void *arg) {
  struct PageflagSamplerArg *sampler = (struct PageflagSamplerArg *) arg;
  struct timespec wait_time = {
    .tv_sec = sampler->sample_period_ns_ / 1000000000UL,
    .tv_nsec = sampler->sample_period_ns_ % 1000000000UL
  };
  KPageFlagsEntryExtended old_page_flags = {0};
  KPageFlagsEntryExtended page_flags = {0};

  // always print initial flags
  if(getKPageFlagsEntryPfn(sampler->pageflags_fd_, &old_page_flags.page_flags, sampler->target_pfn_) != 0)
  {
    __atomic_store_n(&sampler->running_, 1, __ATOMIC_RELAXED);
    return NULL;
  }
  printPageflags(&old_page_flags.page_flags);

  __atomic_store_n(&sampler->running_, 1, __ATOMIC_RELAXED);
  while(__atomic_load_n(&sampler->run_, __ATOMIC_RELAXED)) {
    // sample again
    if(getKPageFlagsEntryPfn(sampler->pageflags_fd_, &page_flags.page_flags, sampler->target_pfn_) != 0)
    {
      return NULL;
    }
    // only print if a change occured
    if(page_flags.raw != old_page_flags.raw) {
      printPageflags(&page_flags.page_flags);
    }

    old_page_flags = page_flags;
    nanosleep(&wait_time, NULL);
  }

  return NULL;
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


void evictPage(FileMapping *eviction_file_mapping, void *victim_addr) {
  volatile uint8_t tmp = 0;
  unsigned char pc_status;
  (void) tmp;

  while(1)
  {
    for(size_t p = 0; p < eviction_file_mapping->size_pages_; p++) 
    {
      // stop as soon as victim page left memory
      mincore(victim_addr, PAGE_SIZE, &pc_status);
      if(!(pc_status & 1)) 
      {
        return;
      }
      tmp = *((uint8_t *) eviction_file_mapping->addr_ + p * PAGE_SIZE);
      // stop as soon as victim page left memory
      mincore(victim_addr, PAGE_SIZE, &pc_status);
      if(!(pc_status & 1)) 
      {
        return;
      }
    }
  }
  posix_fadvise(eviction_file_mapping->fd_, 0, 0, POSIX_FADV_DONTNEED);  
}

void flushExclusivePage(FileMapping *mapping, size_t page) {
  unsigned char pc_status = 0;
  void *target_addr = (uint8_t *) mapping->addr_ + page * PAGE_SIZE;

  // flush target + victim page
  do {
    posix_fadvise(mapping->fd_, page * PAGE_SIZE, PAGE_SIZE, POSIX_FADV_DONTNEED);
    if(mincore(target_addr, PAGE_SIZE, &pc_status) != 0) {
      printf("Warning, error (%s) at mincore\n", strerror(errno));
    }
  } while(pc_status & 1);
}

void usageError(char *program_name)
{
  printf("Usage: %s [mode].\n", program_name);
  for(int i = MIN_MODE; i <= MAX_MODE; i++)
  {
    printf("%d: \t%s\n", i, experiment_strings[i]);
  }
}
