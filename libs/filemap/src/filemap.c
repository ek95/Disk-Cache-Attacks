#define _GNU_SOURCE
#define _WIN32_WINNT 0x0602

#include "filemap.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef __linux
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>
#elif defined(_WIN32)
#include "Windows.h"
#endif

static size_t PAGE_SIZE = 0;

#ifdef __linux
static void initInternalFileMapping(struct _FileMappingInternal_ *internal)
{
  internal->fd_ = -1;
  internal->page_status_ = NULL;
}
#elif defined(_WIN32)
static void initInternalFileMapping(struct _FileMappingInternal_ *internal)
{
  internal->file_handle_ = INVALID_HANDLE_VALUE;
  internal->mapping_handle_ = INVALID_HANDLE_VALUE;
  internal->page_status_ = NULL;
}
#endif

void initFileMapping(FileMapping *file_mapping)
{
  memset(file_mapping, 0, sizeof(FileMapping));
  initInternalFileMapping(&file_mapping->internal_);
}

#ifdef __linux
static inline int fileFlags2openFlags(int file_flags)
{
  int flags = 0;

  if ((file_flags & FILE_ACCESS_READ) && (file_flags & FILE_ACCESS_WRITE))
  {
    flags |= O_RDWR;
  }
  else if (file_flags & FILE_ACCESS_READ)
  {
    flags |= O_RDONLY;
  }
  else if (file_flags & FILE_ACCESS_WRITE)
  {
    flags |= O_WRONLY;
  }

  return flags;
}

static inline int mappingFlags2mmapProtection(int mapping_flags)
{
  int flags = 0;

  flags |= (mapping_flags & MAPPING_ACCESS_READ) ? PROT_READ : 0;
  flags |= (mapping_flags & MAPPING_ACCESS_WRITE) ? PROT_WRITE : 0;
  flags |= (mapping_flags & MAPPING_ACCESS_EXECUTE) ? PROT_EXEC : 0;

  return flags;
}

static inline int mappingFlags2mmapFlags(int mapping_flags)
{
  int flags = 0;

  flags |= (mapping_flags & MAPPING_PRIVATE) ? MAP_PRIVATE : 0;
  flags |= (mapping_flags & MAPPING_SHARED) ? MAP_SHARED : 0;

  return flags;
}

int mapFile(FileMapping *file_mapping, const char *file_path, int file_flags, int mapping_flags)
{
  struct stat file_stat;

  // fetch system PAGE_SIZE if not done alreay
  if (PAGE_SIZE == 0)
  {
    long res = sysconf(_SC_PAGESIZE);
    PAGE_SIZE = (res != -1) ? res : DEF_PAGE_SIZE;
  }


  // open file (if not already done)
  if(file_mapping->internal_.fd_ == -1) {
    file_mapping->internal_.fd_ = open(file_path, fileFlags2openFlags(file_flags));
    if (file_mapping->internal_.fd_ == -1)
    {
      goto error;
    }
  }

  if (fstat(file_mapping->internal_.fd_, &file_stat) != 0)
  {
    goto error;
  }

  file_mapping->size_ = file_stat.st_size;
  file_mapping->size_pages_ = (file_stat.st_size + PAGE_SIZE - 1) / PAGE_SIZE;
  file_mapping->addr_ =
      mmap(NULL, file_mapping->size_, mappingFlags2mmapProtection(mapping_flags),
           mappingFlags2mmapFlags(mapping_flags), file_mapping->internal_.fd_, 0);
  if (file_mapping->addr_ == MAP_FAILED)
  {
    file_mapping->addr_ = NULL;
    goto error;
  }

  return 0;

error:

  closeFileMapping(file_mapping);
  return -1;
}

void closeMappingOnly(void *arg) {
  FileMapping *file_mapping = arg;
  if (file_mapping->addr_ != NULL)
  {
    munmap(file_mapping->addr_, file_mapping->size_);
    file_mapping->addr_ = NULL;
  }
  // free state also here, remapping might update size
  free(file_mapping->internal_.page_status_);
  file_mapping->internal_.page_status_ = NULL;
}

void closeFileMapping(void *arg)
{
  FileMapping *file_mapping = arg;

  closeMappingOnly(arg);
  if (file_mapping->internal_.fd_ >= 0)
  {
    close(file_mapping->internal_.fd_);
    file_mapping->internal_.fd_ = -1;
  }
}
#elif defined(_WIN32)
static inline DWORD fileFlags2createFileAccess(int file_flags)
{
  DWORD flags = 0;

  flags |= (mapping_flags & FILE_ACCESS_READ) ? GENERIC_READ : 0;
  flags |= (mapping_flags & FILE_ACCESS_WRITE) ? GENERIC_WRITE : 0;

  return flags;
}

static inline DWORD fileFlags2createFileFlags(int file_flags)
{
  DWORD flags = 0;

  flags |= (mapping_flags & FILE_USAGE_RANDOM) ? FILE_FLAG_RANDOM_ACCESS : 0;
  flags |= (mapping_flags & FILE_USAGE_SEQUENTIAL) ? FILE_FLAG_SEQUENTIAL_SCAN : 0;

  return flags;
}

static inline DWORD mappingFlags2createFileMappingProtection(int mapping_flags)
{
  DWORD flags = 0;

  if(mapping_flags & MAPPING_ACCESS_READ) {
    if(mapping_flags & MAPPING_ACCESS_EXECUTE) {
      flags = PAGE_EXECUTE_READ;
    }
    else {
      flags = PAGE_READONLY;
    }
  }

  // in windows no write only exists (write implies read)
  if(mapping_flags & MAPPING_ACCESS_WRITE) {
    if(mapping_flags & MAPPING_ACCESS_EXECUTE) {
      flags = PAGE_EXECUTE_READWRITE;
    }
    else {
      flags = PAGE_EXECUTE_READ;
    }
  }

  flags |= (mapping_flags & MAPPING_LARGE_PAGES) ? SEC_LARGE_PAGES : 0;

  return flags;
}

static inline DWORD mappingFlags2mapViewOfFileAccess(int mapping_flags)
{
  DWORD flags = 0;

  flags |= (mapping_flags & FILE_ACCESS_READ) ? FILE_MAP_READ : 0;
  flags |= (mapping_flags & FILE_ACCESS_WRITE) ? FILE_MAP_WRITE : 0;
  flags |= (mapping_flags & FILE_ACCESS_EXECUTE) ? FILE_MAP_EXECUTE : 0;
  flags |= (mapping_flags & MAPPING_LARGE_PAGES) ? FILE_MAP_LARGE_PAGES : 0;

  return flags;
}

int mapFile(FileMapping *file_mapping, const char *file_path, int file_flags, int mapping_flags)
{
  LARGE_INTEGER file_size;

  // fetch system PAGE_SIZE if not done alreay
  if (PAGE_SIZE == 0)
  {
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    PAGE_SIZE = sys_info.dwPageSize;
  }

  // open file (if not already done)
  if(file_mapping->intern_.file_handle_ == INVALID_HANDLE_VALUE) {
    file_mapping->intern_.file_handle_ = CreateFileA(file_name, fileFlags2createFileAccess(file_flags), 
      FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | fileFlags2createFileFlags(file_flags), NULL);
    if (file_mapping->intern_.file_handle_ == INVALID_HANDLE_VALUE)
    {
      goto error;
    }
  }

  // get file size
  if (!GetFileSizeEx(file_mapping->intern_.file_handle_, &file_size))
  {
    goto error;
  }

  file_mapping->size_ = file_size.QuadPart;
  file_mapping->size_pages_ = ((file_mapping->size_ + PAGE_SIZE - 1) / PAGE_SIZE);
  // map file
  file_mapping->intern_.mapping_handle_ = CreateFileMappingA(file_mapping->intern_.file_handle_, NULL, 
    mappingFlags2createFileMappingProtection(mapping_flags), 0, 0, NULL); 
  if(file_mapping->intern_.mapping_handle_ == NULL)
  {
    goto error;
  }
  file_mapping->addr_ = MapViewOfFile(file_mapping->intern_.mapping_handle_, 
    mappingFlags2mapViewOfFileAccess(mapping_flags), 0, 0, 0);
  if(file_mapping->addr_ == NULL)
  {
    goto error;
  }

  return 0;

error:

  closeFileMapping(file_mapping);
  return -1;
}

void closeMappingOnly(void *arg) {
  FileMapping *file_mapping = arg;
 
  if(file_mapping->intern_.addr_ != NULL)
  {
      UnmapViewOfFile(file_mapping->intern_.addr_);
      file_mapping->intern_.addr_ = NULL;
  }
  if(file_mapping->intern_.mapping_handle_ != INVALID_HANDLE_VALUE) 
  {
      CloseHandle(file_mapping->intern_.mapping_handle_);
      file_mapping->intern_.mapping_handle_ = INVALID_HANDLE_VALUE;
  }
  // free state also here, remapping might update size
  free(file_mapping->internal_.page_status_);
  file_mapping->internal_.page_status_ = NULL;
}

void closeFileMapping(void *arg)
{
  FileMapping *file_mapping = arg;

  closeMappingOnly(arg);
  if(file_mapping->intern_.file_handle_ != INVALID_HANDLE_VALUE) 
  {
    CloseHandle(file_mapping->intern_.file_handle_);
    file_view->file_handle_ = INVALID_HANDLE_VALUE;
  }
}
#endif

#ifdef __linux
int adviseFileUsage(FileMapping *file_mapping, size_t offset, size_t len, int advice)
{
  int ret = 0;

  // advice value directly compatible with linux
  if (madvise((uint8_t *)(file_mapping->addr_) + offset, len, advice) == -1)
  {
    return -1;
  }

  return posix_fadvise(file_mapping->internal_.fd_, offset, len, advice);
}
#else if defined(_WIN32)
int adviseFileUsage(FileMapping *file_mapping, size_t offset, size_t len, int advice)
{
  // manual range check
  if (len > file_mapping->size_ ||
      offset > file_mapping->size_ - len)
  {
    return -1;
  }

  // only dontneed and willneed are supported
  if (advice == USAGE_DONTNEED)
  {
    // double unlock always removes pages from working set
    // see https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualunlock
    VirtualUnlock((uint8_t *)(file_mapping->addr_) + offset, len);
    VirtualUnlock((uint8_t *)(file_mapping->addr_) + offset, len);
    return 0;
  }
  else if (advice == USAGE_WILLNEED)
  {
    WIN32_MEMORY_RANGE_ENTRY range = {
        .VirtualAddress = (uint8_t *)(file_mapping->addr_) + offset,
        .NumberOfBytes = len};

    return PrefetchVirtualMemory(GetCurrentProcess(), 1, &range, 0) == 0 ? -1 : 0;
  }

  return -1;
}
#endif

#ifdef __linux
// all functions that might fail set errno so errno can be used to get more info
int createRandomFile(char *filename, size_t size)
{
  int fd;
  struct stat file_stat;
  struct statvfs filesys_stat;
  char cwd[PATH_MAX] = {0};

  // open file or if already exists check if current size, else overwrite
  fd = open(filename, O_CREAT | O_WRONLY | O_EXCL, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if (fd < 0)
  {
    if (errno != EEXIST)
    {
      return -1;
    }

    // file already exists check size
    if (stat(filename, &file_stat) != 0)
    {
      return -1;
    }
    // too small, recreate
    if (file_stat.st_size < size)
    {
      close(fd);
      fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
      if (fd < 0)
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
  if (getcwd(cwd, sizeof(cwd)) == NULL)
  {
    return -1;
  }
  // check if enough space disk space
  if (statvfs(cwd, &filesys_stat) != 0)
  {
    return -1;
  }

  // sanity checks
  size_t free_disk = filesys_stat.f_bsize * filesys_stat.f_bavail;
  if (free_disk < size)
  {
    errno = ENOSPC;
    return -1;
  }

  // try fallocate first, if it fails fall back to the much slower file copy
  if (fallocate(fd, 0, 0, size) != 0)
  {
    // fallocate failed, fall back to creating eviction file from /dev/urandom
    close(fd);

    FILE *rnd_file = fopen(RANDOM_SOURCE_PATH, "rb");
    if (rnd_file == NULL)
    {
      return -1;
    }
    FILE *target_file = fopen(filename, "wb");
    if (target_file == NULL)
    {
      return -1;
    }
    size_t bs = FILE_COPY_BS;
    size_t rem = size;

    char *block = malloc(bs);
    if (block == NULL)
    {
      return -1;
    }

    while (rem)
    {
      if (fread(block, bs, 1, rnd_file) != 1)
      {
        fclose(rnd_file);
        fclose(target_file);
        free(block);
        return -1;
      }
      if (fwrite(block, bs, 1, target_file) != 1)
      {
        fclose(rnd_file);
        fclose(target_file);
        free(block);
        return -1;
      }
      if (rem >= bs)
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
#elif defined(_WIN32)
int createRandomFile(char *filename, size_t size)
{
  LARGE_INTEGER file_size;
  HANDLE random_file = NULL;
  char *buff = malloc(PAGE_SIZE);
  if (buff == NULL)
  {
    printf(FAIL "Error (%s) at malloc...\n", strerror(errno));
    return -1;
  }

  // file does already exist
  if (PathFileExistsA(filename))
  {
    random_file = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (random_file == INVALID_HANDLE_VALUE)
    {
      printf(FAIL "Error (%d) at CreateFileA: %s...\n", GetLastError(), filename);
      return -1;
    }

    // get size of random file
    if (!GetFileSizeEx(random_file, &file_size))
    {
      printf(FAIL "Error (%d) at GetFileSizeEx: %s...\n", GetLastError(), filename);
      CloseHandle(random_file);
      return -1;
    }

    CloseHandle(random_file);

    if (file_size.QuadPart >= size)
    {
      printf(OK "File %s already exists...\n", filename);
      return 0;
    }
  }

  // create new file
  printf(PENDING "Creating %Iu MB random file. This might take a while...\n", size / 1024 / 1024);
  random_file = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (random_file == INVALID_HANDLE_VALUE)
  {
    printf(FAIL "Error (%d) at CreateFileA: %s...\n", GetLastError(), filename);
    return -1;
  }

  for (size_t p = 0; p < size; p += PAGE_SIZE)
  {
    if (BCryptGenRandom(NULL, (BYTE *)buff, PAGE_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS)
    {
      printf(FAIL "Error (%d) at BCryptGenRandom...\n", GetLastError());
      CloseHandle(random_file);
      return -1;
    }

    if (!WriteFile(random_file, buff, PAGE_SIZE, NULL, NULL))
    {
      printf(FAIL "Error (%d) at WriteFile...\n", GetLastError());
      CloseHandle(random_file);
      return -1;
    }
  }

  CloseHandle(random_file);
  return 0;
}
#endif