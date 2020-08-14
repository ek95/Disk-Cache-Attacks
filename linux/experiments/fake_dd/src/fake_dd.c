#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>


int main(int argc, char *argv[]) {
  int ifd, ofd;
  size_t block_size;
  size_t count;
  size_t offset;
  uint8_t *buf;
  struct timespec start, end;
  size_t consumed_time;

  if(argc != 6) {
    printf("%s <ifile> <ioffset> <ofile> <block size> <count>\n", argv[0]);
    return 0;
  }

  ifd = open(argv[1], O_RDONLY);
  if(ifd < 0)
  {
    printf("Error (%s) at opening file: %s\n", strerror(errno), argv[1]);
    return -1;
  }

  ofd = open(argv[3], O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU);
  if(ofd < 0)
  {
    printf("Error (%s) at opening file: %s\n", strerror(errno), argv[3]);
    close(ifd);
    return -1;
  }

  offset = strtoul(argv[2], NULL, 10);
  block_size = strtoul(argv[4], NULL, 10);
  count = strtoul(argv[5], NULL, 10);

  buf = malloc(block_size);
  if(buf == NULL)
  {
    printf("Error (%s) at malloc.\n", strerror(errno));
    close(ifd);
    close(ofd);
    return -1;
  }

  lseek(ifd, offset, SEEK_SET);

  size_t processed_bytes = 0;
  size_t written_bytes = 0;
  ssize_t read_bytes = 0;
  ssize_t ret = 0;

  clock_gettime(CLOCK_MONOTONIC, &start);
  while(processed_bytes < count * block_size)
  {
    read_bytes = read(ifd, buf, block_size);
    if(read_bytes == 0)
    {
      continue;
    }
    else if(read_bytes < 0)
    {
        printf("Error (%s) at read.\n", strerror(errno));
        close(ifd);
        close(ofd);
        free(buf);
        return -1;
    }

    written_bytes = 0;
    while(written_bytes != read_bytes)
    {
      ret = write(ofd, buf, read_bytes);
      if(ret < 0)
      {
        printf("Error (%s) at write.\n", strerror(errno));
        close(ifd);
        close(ofd);
        free(buf);
        return -1;
      }

      written_bytes+= ret;
    }

    processed_bytes += read_bytes;
  }
  clock_gettime(CLOCK_MONOTONIC, &end);

  consumed_time = (end.tv_sec - start.tv_sec) * 1000000000 + (end.tv_nsec - start.tv_nsec);
  printf("%zu bytes transferred in %zu ns (%f kB/s)\n", count * block_size, consumed_time, (float) count * block_size / ((float) consumed_time / 1000000));

  fdatasync(ofd);

  free(buf);
  close(ifd);
  close(ofd);
  return 0;
}
