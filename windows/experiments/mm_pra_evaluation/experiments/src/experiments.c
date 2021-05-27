// target windows 8 and higher
#define _WIN32_WINNT 0x0602

#include <Shlwapi.h>
#include <errno.h>
#include <ntstatus.h>
#include <psapi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>

#include "filemap.h"

#define ARG_COUNT 2
#define MODE_ARG 1

#define EVICTION_FILENAME "eviction.ram"
#define EVICTION2_FILENAME "eviction2.ram"

#define TEST_EXEC_FILE_PATH "test.so"
#define TEST_READ_FILE_PATH "test.dat"
#define TEST_WRITE_FILE_PATH "test-wr.dat"
#define TEST_FILE_SIZE (2 * 1024 * 1024ULL)
// last page
#define TEST_FILE_TARGET_PAGE (0x1ff)
// outside of first page-in block
#define TEST_FILE_VICTIM_PAGE (0x20)
#define TEST_FILE_VICTIM_PAGE2 (0x100)

#define READ_CLEAN_FILE_PAGE_1 0
#define ACCESS_READ_CLEAN_FILE_PAGE_1 1
#define WRITE_FILE_PAGE_1 2
#define ACCESS_WRITE_FILE_PAGE_1 3
#define READ_EXEC_FILE_PAGE_1 4
#define ACCESS_READ_EXEC_FILE_PAGE_1 5
#define MIN_MODE READ_CLEAN_FILE_PAGE_1
#define MAX_MODE ACCESS_READ_EXEC_FILE_PAGE_1

#define WAIT_TIME_NS (100 * 1000 * 1000ULL)

#define DEBUG

#ifdef DEBUG
#define DEBUG_PRINT(x) printf x
#else
#define DEBUG_PRINT(x) \
  do                   \
  {                    \
  } while (0)
#endif

const char *experiment_strings[] =
  {
      "read read-only file once",
      "access (read) mapped read-only file once",
      "write file once",
      "access (write) mapped file once",
      "read executable file once",
      "access (read) mapped executable file once"
  };

size_t PAGE_SIZE = 0;
LARGE_INTEGER pc_frequency = { 0 };

void usageError(char *app_name);

int main(int argc, char *argv[])
{
  int ret = 0;
  int mode = 0;
  SYSTEM_INFO sys_info;
  FileMapping test_read_file_mapping, test_exec_file_mapping, test_write_file_mapping;
  volatile uint8_t tmp = 0;
  uint8_t *exec_target_addr = NULL, *read_target_addr = NULL, *write_target_addr = NULL;
  uint8_t *exec_victim_addr = NULL, *read_victim_addr = NULL, *read_victim2_addr = NULL, *write_victim_addr = NULL;
  //unsigned char pc_status = 0;
  DWORD read_bytes = 0;
  DWORD written_bytes = 0;
  (void)tmp;

  initFileMapping(&test_read_file_mapping);
  initFileMapping(&test_exec_file_mapping);
  initFileMapping(&test_write_file_mapping);

  if (argc != ARG_COUNT)
  {
    usageError(argv[0]);
    goto error;
  }
  // parse mode and check if valid
  mode = atoi(argv[MODE_ARG]);
  if (mode < MIN_MODE || mode > MAX_MODE)
  {
    usageError(argv[0]);
    goto error;
  }

  // get system page size
  GetSystemInfo(&sys_info);
  PAGE_SIZE = sys_info.dwPageSize;

  // retrieve frequency of performance counter
  QueryPerformanceFrequency(&pc_frequency);

  // create test file
  if (createRandomFile(TEST_READ_FILE_PATH, TEST_FILE_SIZE) != 0)
  {
    printf("Error (%ld) at createRandomFile\n", GetLastError());
    goto error;
  }
  // create test file
  if (createRandomFile(TEST_EXEC_FILE_PATH, TEST_FILE_SIZE) != 0)
  {
    printf("Error (%ld) at createRandomFile\n", GetLastError());
    goto error;
  }
  // create test file
  if (createRandomFile(TEST_WRITE_FILE_PATH, TEST_FILE_SIZE) != 0)
  {
    printf("Error (%ld) at createRandomFile\n", GetLastError());
    goto error;
  }

  // map test file non-executable
  if (mapFile(&test_read_file_mapping, TEST_READ_FILE_PATH, FILE_ACCESS_READ, MAPPING_ACCESS_READ | MAPPING_SHARED) != 0)
  {
    printf("Error (%ld) at mapFile for: %s ...\n", GetLastError(), TEST_READ_FILE_PATH);
    goto error;
  }
  // map test file executable
  if (mapFile(&test_exec_file_mapping, TEST_EXEC_FILE_PATH, FILE_ACCESS_READ | FILE_ACCESS_EXECUTE, MAPPING_ACCESS_READ | MAPPING_ACCESS_EXECUTE | MAPPING_SHARED) != 0)
  {
    printf("Error (%ld) at mapFile for: %s ...\n", GetLastError(), TEST_EXEC_FILE_PATH);
    goto error;
  }
  // map test file writeable
  if (mapFile(&test_write_file_mapping, TEST_WRITE_FILE_PATH, FILE_ACCESS_READ | FILE_ACCESS_WRITE, MAPPING_ACCESS_READ | MAPPING_ACCESS_WRITE | MAPPING_SHARED) != 0)
  {
    printf("Error (%ld) at mapFile for: %s ...\n", GetLastError(), TEST_WRITE_FILE_PATH);
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

  // use RamMap tool to check caching state
  if (mode == READ_CLEAN_FILE_PAGE_1)
  {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    // set file pointer
    LARGE_INTEGER off = {
      .QuadPart = TEST_FILE_VICTIM_PAGE * PAGE_SIZE
    };
    if (!SetFilePointerEx(test_read_file_mapping.internal_.file_handle_, off, NULL, FILE_BEGIN))
    {
      printf("Error (%ld) at SetFilePointerEx\n", GetLastError());
      goto error;
    }
    // read access
    if (!ReadFile(test_read_file_mapping.internal_.file_handle_, (void *) &tmp, sizeof(uint8_t), &read_bytes, NULL))
    {
      printf("Error (%ld) at ReadFile\n", GetLastError());
      goto error;
    }
  }
  else if (mode == ACCESS_READ_CLEAN_FILE_PAGE_1)
  {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    printf("Reading from %p\n", read_victim_addr);
    tmp = *read_victim_addr;
  }
  else if (mode == WRITE_FILE_PAGE_1)
  {
    tmp = 0x00;
    // set file pointer
    LARGE_INTEGER off = {
      .QuadPart = TEST_FILE_VICTIM_PAGE * PAGE_SIZE
    };

    // reset data
    if (!SetFilePointerEx(test_write_file_mapping.internal_.file_handle_, off, NULL, FILE_BEGIN))
    {
      printf("Error (%ld) at SetFilePointerEx\n", GetLastError());
      goto error;
    }
    if (!WriteFile(test_write_file_mapping.internal_.file_handle_, (void *) &tmp, sizeof(uint8_t), &written_bytes, NULL))
    {
      printf("Error (%ld) at WriteFile\n", GetLastError());
      goto error;
    }
    if (!FlushFileBuffers(test_write_file_mapping.internal_.file_handle_)) 
    {
      printf("Error (%ld) at FlushFileBuffers\n", GetLastError());
      goto error;
    }

    // new data
    tmp = 0xFF;
    if (!SetFilePointerEx(test_write_file_mapping.internal_.file_handle_, off, NULL, FILE_BEGIN))
    {
      printf("Error (%ld) at SetFilePointerEx\n", GetLastError());
      goto error;
    }
    // write access
    if (!WriteFile(test_write_file_mapping.internal_.file_handle_, (void *) &tmp, sizeof(uint8_t), &written_bytes, NULL))
    {
      printf("Error (%ld) at WriteFile\n", GetLastError());
      goto error;
    }
  }
  else if (mode == ACCESS_WRITE_FILE_PAGE_1)
  {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));

    // reset data
    *write_victim_addr = 0x00;
    if (!FlushViewOfFile(test_write_file_mapping.addr_, 0)) 
    {
      printf("Error (%ld) at FlushViewOfFile\n", GetLastError());
      goto error;
    }

    // new data
    *write_victim_addr = 0xFF;
  }
  else if (mode == READ_EXEC_FILE_PAGE_1)
  {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    // set file pointer
    LARGE_INTEGER off = {
      .QuadPart = TEST_FILE_VICTIM_PAGE * PAGE_SIZE
    };
    if (!SetFilePointerEx(test_exec_file_mapping.internal_.file_handle_, off, NULL, FILE_BEGIN))
    {
      printf("Error (%ld) at SetFilePointerEx\n", GetLastError());
      goto error;
    }
    // read access
    if (!ReadFile(test_exec_file_mapping.internal_.file_handle_, (void *) &tmp, sizeof(uint8_t), &read_bytes, NULL))
    {
      printf("Error (%ld) at ReadFile\n", GetLastError());
      goto error;
    }
  }
  else if (mode == ACCESS_READ_EXEC_FILE_PAGE_1)
  {
    DEBUG_PRINT(("Executing experiment: %i\n", mode));
    printf("Reading from %p\n", exec_victim_addr);
    tmp = *exec_victim_addr;
  }

  printf("Press key to exit...\n");
  getchar();

  goto cleanup;
error:

  ret = -1;

cleanup:

  closeFileMapping(&test_exec_file_mapping);
  closeFileMapping(&test_read_file_mapping);
  closeFileMapping(&test_write_file_mapping);
  return ret;
}

/*int waitUntilWrittenBack(char *path, size_t offset, uint8_t magic_byte) 
{
  int ret = 0;
  LARGE_INTEGER start_ts = {0}, end_ts = {0};
  size_t elapsed_time_ns = 0;
  HANDLE file_handle = INVALID_HANDLE_VALUE;
  uint8_t sector[512] = { 0 };
  LARGE_INTEGER off = {
    .QuadPart = offset
  };
  DWORD read_bytes = 0;

  QueryPerformanceCounter(&start_ts);
  // open file without buffering
  file_handle = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING, NULL);
  if(file_handle == INVALID_HANDLE_VALUE) 
  {
    printf("Error (%ld) at CreateFileA\n", GetLastError());
    goto error; 
  }

  // wait until magic byte is found at position
  while(1)
  {
    // (re)set offset
    if (!SetFilePointerEx(file_handle, off, NULL, FILE_BEGIN))
    {
      printf("Error (%ld) at SetFilePointerEx\n", GetLastError());
      goto error;
    }
    // read access
    if (!ReadFile(file_handle, (void *) &sector, 512, &read_bytes, NULL))
    {
      printf("Error (%ld) at ReadFile\n", GetLastError());
      goto error;
    }
    // check
    if(sector[0] == magic_byte) {
      break;
    }

    // yield
    SwitchToThread();
  }
  QueryPerformanceCounter(&end_ts);
  elapsed_time_ns = (end_ts.QuadPart - start_ts.QuadPart) * 1000000000UL;
  elapsed_time_ns /= pc_frequency.QuadPart;

  printf("Took %Iu ns until dirty page was written back!\n", elapsed_time_ns);

goto cleanup;
error:
  ret = -1;

cleanup:
  if (file_handle != INVALID_HANDLE_VALUE) 
  {
    CloseHandle(file_handle);
  }

  return ret;
}*/

void usageError(char *program_name)
{
  printf("Usage: %s [mode].\n", program_name);
  for (int i = MIN_MODE; i <= MAX_MODE; i++)
  {
    printf("%d: \t%s\n", i, experiment_strings[i]);
  }
}
