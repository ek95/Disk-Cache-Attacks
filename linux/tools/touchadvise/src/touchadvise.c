#define _GNU_SOURCE

#include "filemap.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define TARGET_FILE_ARG 1
#define ARG_COUNT (TARGET_FILE_ARG + 1)

#define INPUT_LINE_SIZE 255

size_t PAGE_SIZE = 0;

void usageError(char *program_name);

int main(int argc, char *argv[])
{
  int ret = 0;
  char input[INPUT_LINE_SIZE] = {0};
  char last_input[INPUT_LINE_SIZE] = {0};
  char choice = 0;
  char *endptr = NULL;
  FileMapping file_mapping;
  volatile uint8_t tmp = 0;
  (void)tmp;

  initFileMapping(&file_mapping);

  if (argc != ARG_COUNT)
  {
    usageError(argv[0]);
    goto error;
  }

  PAGE_SIZE = sysconf(_SC_PAGESIZE);
  if (PAGE_SIZE == -1)
  {
    printf("Error (%s) at sysconf\n", strerror(errno));
    goto error;
  }

  printf("Mapping file %s into memory...\n", argv[1]);
  if (mapFile(&file_mapping, argv[TARGET_FILE_ARG], FILE_ACCESS_READ, MAPPING_ACCESS_READ | MAPPING_ACCESS_EXECUTE | MAPPING_SHARED) != 0)
  {
    printf("Error (%s) at mapFile for: %s ...\n", strerror(errno), argv[TARGET_FILE_ARG]);
    goto error;
  }

  // ensure file is flushed
  madvise(file_mapping.addr_, file_mapping.size_, MADV_DONTNEED);
  posix_fadvise(file_mapping.internal_.fd_, file_mapping.size_, 0, POSIX_FADV_DONTNEED);

  while (1)
  {
    printf("\nq -> quit\n"
           "a <offset in pages as hex> <range in pages as hex> -> access pages\n"
           "m <offset in pages as hex> <range in pages as hex> <advice as hex> -> tell kernel how region is used\n");
    printf("> ");
    if (fgets(input, INPUT_LINE_SIZE, stdin) == NULL)
    {
      printf("Faulty input, exiting...\n");
      goto error;
    }

  reparse:
    choice = input[0];
    // repeat last command
    if (choice == '\n' && last_input[0] != 0)
    {
      strcpy(input, last_input);
      goto reparse;
    }
    else
    {
      // save current input
      strcpy(last_input, input);
    }

    if (choice == 'q')
    {
      break;
    }
    else if (choice == 'a' || choice == 'm')
    {
      char *arg = NULL;
      size_t offset = 0;
      size_t range = 0;
      int advice = 0;

      // parse arguments
      strtok(input, " ");

      arg = strtok(NULL, " ");
      if (arg == NULL)
      {
        printf("Invalid syntax!\n");
        continue;
      }
      offset = strtoul(arg, NULL, 16) * PAGE_SIZE;
      if (offset > file_mapping.size_)
      {
        printf("Out of range!\n");
        continue;
      }

      arg = strtok(NULL, " ");
      if (arg == NULL)
      {
        printf("Invalid syntax!\n");
        continue;
      }
      range = strtoul(arg, NULL, 16) * PAGE_SIZE;
      if (range == 0)
      {
        range = file_mapping.size_;
      }
      if (offset + range > file_mapping.size_)
      {
        printf("Out of range!\n");
        continue;
      }

      if (choice == 'm')
      {
        arg = strtok(NULL, " ");
        if (arg == NULL)
        {
          printf("Invalid syntax!\n");
          continue;
        }
        advice = strtol(arg, NULL, 16);
      }

      if (choice == 'a')
      {
        // access pages
        for (size_t current = offset; current < (offset + range); current += PAGE_SIZE)
        {
          tmp = *((uint8_t *)file_mapping.addr_ + current);
        }
      }
      else if (choice == 'm')
      {
        printf("%lx %lx %d\n", offset, range, advice);
        if (madvise((uint8_t *)file_mapping.addr_ + offset, range, advice) != 0)
        {
          printf("madvise failed: %s!", strerror(errno));
        }
      }
    }
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
  printf("Usage: %s [file to map].\n", program_name);
}
