#define _GNU_SOURCE
#define _DEFAULT_SOURCE
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
#include <sys/uio.h>
#include <unistd.h>
#elif defined(_WIN32)
#include "Windows.h"
#endif

// forward declarations
#ifdef __linux
int doFcStateMincore(FileMapping *file_mapping, size_t offset, size_t len, uint8_t *vec);
int doFcStatePreadV2(FileMapping *file_mapping, size_t offset, size_t len, uint8_t *vec);
#elif defined(_WIN32)
int doFcStateQueryWorkingSetEx(FileMapping *file_mapping, size_t offset, size_t len, uint8_t *vec);
#endif

// globals
static size_t PAGE_SIZE = 0;
#ifdef __linux
static FcStateFn FC_STATE_FN = doFcStateMincore;
#elif defined(_WIN32)
static FcStateFn FC_STATE_FN = doFcStateQueryWorkingSetEx;
#endif

#ifdef __linux
static void initInternalFileMapping(struct _FileMappingInternal_ *internal)
{
  // fetch system PAGE_SIZE if not done alreay
  if (PAGE_SIZE == 0)
  {
    long res = sysconf(_SC_PAGESIZE);
    PAGE_SIZE = (res != -1) ? res : DEF_PAGE_SIZE;
  }

  internal->fd_ = -1;
}
#elif defined(_WIN32)
static void initInternalFileMapping(struct _FileMappingInternal_ *internal)
{
  // fetch system PAGE_SIZE if not done alreay
  if (PAGE_SIZE == 0)
  {
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    PAGE_SIZE = sys_info.dwPageSize;
  }

  internal->file_handle_ = INVALID_HANDLE_VALUE;
  internal->mapping_handle_ = INVALID_HANDLE_VALUE;
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

  // open file (if not already done)
  if (file_mapping->internal_.fd_ == -1)
  {
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

// advice values directly compatible with linux
static int adviseFileUsageIntern(FileMapping *file_mapping, size_t offset, size_t len, int advice)
{
  int ret = 0;

  // no file descriptor
  if (file_mapping->internal_.fd_ == -1)
  {
    return -1;
  }

  // only if address exists
  if (file_mapping->addr_ != NULL &&
      madvise((uint8_t *)(file_mapping->addr_) + offset, len, advice) == -1)
  {
    return -1;
  }

  return posix_fadvise(file_mapping->internal_.fd_, offset, len, advice);
}

static void closeMappingOnlyIntern(FileMapping *file_mapping)
{
  if (file_mapping->addr_ != NULL)
  {
    munmap(file_mapping->addr_, file_mapping->size_);
    file_mapping->addr_ = NULL;
  }
}

static void closeFileMappingIntern(FileMapping *file_mapping)
{
  if (file_mapping->internal_.fd_ >= 0)
  {
    close(file_mapping->internal_.fd_);
    file_mapping->internal_.fd_ = -1;
  }
}

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
    size_t rem = size;

    char *block = malloc(FILE_COPY_BS);
    if (block == NULL)
    {
      return -1;
    }

    while (rem)
    {
      if (fread(block, FILE_COPY_BS, 1, rnd_file) != 1)
      {
        fclose(rnd_file);
        fclose(target_file);
        free(block);
        return -1;
      }
      if (fwrite(block, FILE_COPY_BS, 1, target_file) != 1)
      {
        fclose(rnd_file);
        fclose(target_file);
        free(block);
        return -1;
      }
      if (rem >= FILE_COPY_BS)
      {
        rem -= FILE_COPY_BS;
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

static int doFcStateMincore(FileMapping *file_mapping, size_t offset, size_t len, uint8_t *vec)
{
  return mincore((uint8_t *)file_mapping->addr_ + offset, len, vec);
}

static int doFcStatePreadV2(FileMapping *file_mapping, size_t offset, size_t len, uint8_t *vec)
{
  int ret = 0;
  volatile uint8_t tmp = 0;
  (void)tmp;
  struct iovec io_range = {0};
  io_range.iov_base = (void *)&tmp;
  io_range.iov_len = sizeof(tmp);

  for (size_t current_ofs = offset; current_ofs < (offset + len); current_ofs += PAGE_SIZE, vec++)
  {
    ret = preadv2(file_mapping->internal_.fd_, &io_range, 1, current_ofs, RWF_NOWAIT);
    if (ret == -1)
    {
      if (errno == EAGAIN)
      {
        *vec = 0;
      }
      else
      {
        return ret;
      }
    }
    else
    {
      *vec = 1;
    }
  }

  return 0;
}

int changeFcStateSource(int source)
{
  if (source == FC_SOURCE_MINCORE)
  {
    FC_STATE_FN = doFcStateMincore;
    return 0;
  }
  else if (source == FC_SOURCE_PREADV2)
  {
    FC_STATE_FN = doFcStatePreadV2;
    return 0;
  }

  return -1;
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

  if (mapping_flags & MAPPING_ACCESS_READ)
  {
    if (mapping_flags & MAPPING_ACCESS_EXECUTE)
    {
      flags = PAGE_EXECUTE_READ;
    }
    else
    {
      flags = PAGE_READONLY;
    }
  }

  // in windows no write only exists (write implies read)
  if (mapping_flags & MAPPING_ACCESS_WRITE)
  {
    if (mapping_flags & MAPPING_ACCESS_EXECUTE)
    {
      flags = PAGE_EXECUTE_READWRITE;
    }
    else
    {
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

  // open file (if not already done)
  if (file_mapping->intern_.file_handle_ == INVALID_HANDLE_VALUE)
  {
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
  if (file_mapping->intern_.mapping_handle_ == NULL)
  {
    goto error;
  }
  file_mapping->addr_ = MapViewOfFile(file_mapping->intern_.mapping_handle_,
                                      mappingFlags2mapViewOfFileAccess(mapping_flags), 0, 0, 0);
  if (file_mapping->addr_ == NULL)
  {
    goto error;
  }

  return 0;

error:

  closeFileMapping(file_mapping);
  return -1;
}

static int adviseFileUsageIntern(FileMapping *file_mapping, size_t offset, size_t len, int advice)
{
  // no mapping
  if (file_mapping->addr_ == NULL)
  {
    return -1;
  }

  // only dontneed and willneed are supported on windows
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

static void closeMappingOnlyIntern(FileMapping *file_mapping)
{
  if (file_mapping->intern_.addr_ != NULL)
  {
    UnmapViewOfFile(file_mapping->intern_.addr_);
    file_mapping->intern_.addr_ = NULL;
  }
  if (file_mapping->intern_.mapping_handle_ != INVALID_HANDLE_VALUE)
  {
    CloseHandle(file_mapping->intern_.mapping_handle_);
    file_mapping->intern_.mapping_handle_ = INVALID_HANDLE_VALUE;
  }
}

static void closeFileMappingIntern(FileMapping *file_mapping)
{
  if (file_mapping->intern_.file_handle_ != INVALID_HANDLE_VALUE)
  {
    CloseHandle(file_mapping->intern_.file_handle_);
    file_mapping->intern_.file_handle_ = INVALID_HANDLE_VALUE;
  }
}

int createRandomFile(char *filename, size_t size)
{
  size_t rem = size;
  LARGE_INTEGER file_size;
  HANDLE random_file = NULL;

  char *buff = malloc(FILE_COPY_BS);
  if (buff == NULL)
  {
    return -1;
  }

  // file does already exist
  if (PathFileExistsA(filename))
  {
    random_file = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (random_file == INVALID_HANDLE_VALUE)
    {
      return -1;
    }

    // get size of random file
    if (!GetFileSizeEx(random_file, &file_size))
    {
      CloseHandle(random_file);
      return -1;
    }

    CloseHandle(random_file);

    if (file_size.QuadPart >= size)
    {
      return 0;
    }
  }

  // create new file
  random_file = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (random_file == INVALID_HANDLE_VALUE)
  {
    return -1;
  }

  for (; rem > FILE_COPY_BS; rem -= FILE_COPY_BS)
  {
    if (BCryptGenRandom(NULL, (BYTE *)buff, FILE_COPY_BS, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS)
    {
      CloseHandle(random_file);
      return -1;
    }
    if (!WriteFile(random_file, buff, FILE_COPY_BS, NULL, NULL))
    {
      CloseHandle(random_file);
      return -1;
    }
  }
  if (BCryptGenRandom(NULL, (BYTE *)buff, rem, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS)
  {
    CloseHandle(random_file);
    return -1;
  }
  if (!WriteFile(random_file, buff, rem, NULL, NULL))
  {
    CloseHandle(random_file);
    return -1;
  }

  CloseHandle(random_file);
  return 0;
}

static int doFcStateQueryWorkingSetEx(FileMapping *file_mapping, size_t offset, size_t len, uint8_t *vec)
{
  PSAPI_WORKING_SET_EX_INFORMATION *ws_infos = NULL;
  size_t offset_pages = offset / PAGE_SIZE;
  size_t len_pages = len / PAGE_SIZE;
  volatile uint8_t tmp;

  ws_infos = malloc(sizeof(PSAPI_WORKING_SET_EX_INFORMATION) * len_pages);
  if (ws_infos == NULL)
  {
    return -1;
  }

  // prepare addresses
  // fetch virtual pages (must be in ws for querying)
  for (size_t p = 0; p < len_pages; p++)
    uint8_t *addr = (uint8_t *)file_mapping->addr_ + (offset_pages + p) * PAGE_SIZE;
  ws_infos[p].VirtualAddress = addr;
  tmp = *addr;
}

// query
if (QueryWorkingSetEx(GetCurrentProcess(), ws_infos, sizeof(PSAPI_WORKING_SET_EX_INFORMATION) * len_pages) == 0)
{
  free(ws_infos);
  return -1;
}

// post process
memset(vec, 0, sizeof(uint8_t) * len_pages);
for (size_t p = 0; p < len_pages; p++)
{
  uint8_t *addr = (uint8_t *)file_mapping->addr_ + (offset_pages + p) * PAGE_SIZE;
  if (!ws_infos[p].VirtualAttributes.Valid || ws_infos[p].VirtualAttributes.ShareCount < 2)
  {
    free(ws_infos);
    return -1;
  }
  vec[p] = ws_infos[p].VirtualAttributes.ShareCount - 1;
}

free(ws_infos);
return 0;
}

int changeFcStateSource(int source)
{
  if (source == FC_SOURCE_QUERY_WORKING_SET)
  {
    FC_STATE_FN = doFcStateQueryWorkingSetEx;
    return 0;
  }

  return -1;
}
#endif


int adviseFileUsage(FileMapping *file_mapping, size_t offset, size_t len, int advice)
{
  // round offset down to full pages
  offset = offset / PAGE_SIZE * PAGE_SIZE;
  // round size up to full pages
  len = (len + PAGE_SIZE - 1) / PAGE_SIZE;

  // manual range check
  if (len > file_mapping->size_ ||
      offset > file_mapping->size_ - len)
  {
    return -1;
  }

  return adviseFileUsageIntern(file_mapping, offset, len, advice);
}


int getCacheStatusFile(FileMapping *file_mapping)
{
  // no mapping
  if (file_mapping->addr_ == NULL)
  {
    return -1;
  }

  if (file_mapping->page_cache_status_ == NULL)
  {
    file_mapping->page_cache_status_ = malloc(sizeof(uint8_t) * file_mapping->size_pages_);
    if (file_mapping->page_cache_status_ == NULL)
    {
      return -1;
    }
  }

  return FC_STATE_FN(file_mapping, 0, PAGE_SIZE, file_mapping->page_cache_status_);
}

int getCacheStatusPageFile(FileMapping *file_mapping, size_t offset, uint8_t *status)
{
  // no mapping
  if (file_mapping->addr_ == NULL)
  {
    return -1;
  }

  return FC_STATE_FN(file_mapping, offset, PAGE_SIZE, status);
}


void closeMappingOnly(void *arg)
{
  FileMapping *file_mapping = arg;

  closeMappingOnlyIntern(file_mapping);
  // free state also here, remapping might update size
  free(file_mapping->page_cache_status_);
  file_mapping->page_cache_status_ = NULL;
}

void closeFileMapping(void *arg)
{
  FileMapping *file_mapping = arg;

  closeMappingOnly(arg);
  closeFileMappingIntern(arg);
}