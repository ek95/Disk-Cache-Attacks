// compile as dll with name poc_dll.dll
// for example with mingw 
// gcc -c poc_dll.c
// gcc -shared -o poc_dll.dll poc_dll.o -Wl,--out-implib,libpoc_dll.a

// target windows 8 and higher
#define _WIN32_WINNT 0x0602

#include <stdio.h>
#include "poc_dll.h"

__stdcall void init(const char *s)
{
  printf("Initialise poc dll...\n");
}

int access(size_t page)
{
  return test[page][0];
}
