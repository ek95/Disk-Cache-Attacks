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


#define ARG_COUNT 2
#define CLUSTER_PAGES 32
#define CLUSTERS_PER_LINE 2
#define INPUT_LINE_SIZE 255

size_t PAGE_SIZE = 0;


void usageError(char *program_name);


int main(int argc, char *argv[])
{
  int ret = 0;
  FileMapping file_mapping;
  unsigned char *page_status = NULL;
  size_t pages_to_show;
  char choice = 0;
  char input[INPUT_LINE_SIZE] = {0};
  char last_input[INPUT_LINE_SIZE] = {0};


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

  // map test file
  if(mapFile(&file_mapping, argv[1], O_RDONLY, PROT_READ, MAP_PRIVATE) != 0)
  {
      printf("Error (%s) at mapFile for: %s ...\n", strerror(errno), argv[0]);
      goto error;
  }
  // avoid readahead
  posix_fadvise(file_mapping.fd_, 0, 0, POSIX_FADV_RANDOM);

  // alloc page status array
  page_status = malloc(file_mapping.size_pages_);
  if(page_status == NULL) {
    printf("Error (%s) at malloc\n", strerror(errno));
    goto error;
  }


  // run
  while(1)
  {
    printf("\nq -> quit, p <pages to show> -> print page status\n");
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
    else if(choice == 'p')
    {
      pages_to_show = file_mapping.size_pages_;

      strtok(input, " ");
      char *arg = strtok(NULL, " ");
      if(arg != NULL) 
      {
        pages_to_show =  strtoul(arg, NULL, 16);
        pages_to_show = (pages_to_show < file_mapping.size_pages_) ? pages_to_show : file_mapping.size_pages_;
      }

      mincore(file_mapping.addr_, pages_to_show * PAGE_SIZE, page_status);
      // go through pages
      printf("\n0x%08lx:\t%d", 0UL, page_status[0] & 1);
      for(size_t page = 1; page < pages_to_show; page++)
       {
          if(page % (CLUSTER_PAGES * CLUSTERS_PER_LINE) == 0) 
          {
            printf("\n0x%08lx:\t", page * PAGE_SIZE);
          }
          else if(page % CLUSTER_PAGES == 0) 
          {
            printf("\t");
          }
          printf("%d", page_status[page] & 1);
      }
      printf("\n");
    }
  }


  goto cleanup;
error:

  ret = -1;

cleanup:

  if(page_status != NULL)
  {
    free(page_status);
  }
  closeFileMapping(&file_mapping);
  return ret;
}


void usageError(char *program_name)
{
  printf("Usage: %s <file to read page cache status>\n", program_name);
}
