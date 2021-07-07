#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#ifdef __linux
#include <unistd.h>
#elif defined(_WIN32)
#include "Windows.h"
#endif
#include "osal.h"
#include "filemap.h"

#define ARG_COUNT 5
#define TARGET_FILE_ARG 1
#define TARGET_PAGE_ARG 2
#define ACCESS_PERIOD_MS_ARG 3
#define ACCESS_COUNT_ARG 4

size_t PAGE_SIZE = 0;

void usageError(char *program_name);

int main(int argc, char *argv[])
{
  int ret = 0;
  char *endptr = NULL;
  size_t target_page = 0;
  size_t access_period_ms = 0;
  size_t access_count = 0;
  FileMapping file_mapping;
  volatile uint8_t tmp = 0;
  (void)tmp;

  initFileMapping(&file_mapping);

  if (argc != ARG_COUNT)
  {
    usageError(argv[0]);
    goto error;
  }

    // get system page size
    PAGE_SIZE = osal_get_page_size();
    if(PAGE_SIZE == -1)
    {
        printf("Error " OSAL_EC_FS " at osal_get_page_size...\n", OSAL_EC);
        goto error;
    }

  target_page = strtoul(argv[TARGET_PAGE_ARG], &endptr, 10);
  if (endptr == argv[TARGET_PAGE_ARG] || *endptr != 0 || (target_page == ULONG_MAX && errno == ERANGE))
  {
    usageError(argv[0]);
    goto error;
  }
  access_period_ms = strtoul(argv[ACCESS_PERIOD_MS_ARG], &endptr, 10);
  if (endptr == argv[ACCESS_PERIOD_MS_ARG] || *endptr != 0 || (access_period_ms == ULONG_MAX && errno == ERANGE))
  {
    usageError(argv[0]);
    goto error;
  }
  access_count = strtoul(argv[ACCESS_COUNT_ARG], &endptr, 10);
  if (endptr == argv[ACCESS_COUNT_ARG] || *endptr != 0 || (access_count == ULONG_MAX && errno == ERANGE))
  {
    usageError(argv[0]);
    goto error;
  }

  printf("Mapping file %s into memory...\n", argv[1]);
  if (mapFile(&file_mapping, argv[TARGET_FILE_ARG], FILE_ACCESS_READ, MAPPING_ACCESS_READ | MAPPING_ACCESS_EXECUTE | MAPPING_SHARED) != 0)
  {
    printf("Error " OSAL_EC_FS " at mapFile...\n", OSAL_EC);
    goto error;
  }

  if (target_page >= file_mapping.size_pages_)
  {
    printf("Error: Page offset is out of bound.\n");
    goto error;
  }

  for (size_t access_nr = 0; access_nr < access_count; access_nr++)
  {
    printf("%zu. Access\n", access_nr + 1);
    tmp = *((uint8_t *)file_mapping.addr_ + target_page * PAGE_SIZE);

    osal_sleep_us(access_period_ms * 1000);
  }

  goto cleanup;
error:

  ret = -1;

cleanup:

  closeFileMapping(&file_mapping);
  return ret;
}

void usageError(char *program_name)
{
  printf("Usage: %s [file to map] [page offset] [access period in ms] [access count].\n", program_name);
}
