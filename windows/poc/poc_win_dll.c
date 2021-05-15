// compile
// for example with mingw
// gcc -o poc_win_dll poc_win_dll.c
// attack function access: .\ev_chk.exe -t .\poc_dll.dll access

// target windows 8 and higher
#define _WIN32_WINNT 0x0602

#include<stdio.h>
#include<windows.h>
#include<synchapi.h>
#include<psapi.h>

typedef int (*ACCESS_FUNC)(size_t page);

int main(int argc, char *argv[])
{
  HINSTANCE pocLib;
  ACCESS_FUNC access;
  PSAPI_WORKING_SET_EX_INFORMATION page_info;
  volatile size_t tmp = 0;

  pocLib = LoadLibrary("poc_dll.dll");
  if(pocLib == NULL)
  {
    printf("Could not open poc_dll.dll...\n");
    return -1;
  }

  access = (ACCESS_FUNC) GetProcAddress(pocLib, "access");
  if(access == NULL)
  {
    printf("Could not get address of access function...\n");
    return -1;
  }

  page_info.VirtualAddress = access;
  size_t i = 0;
  while(1)
  {
    if(i % 40 == 0)
    {
      printf("%Iu. Access:\n", i / 40 + 1);
      tmp += access(1);
    }

    QueryWorkingSetEx(GetCurrentProcess(), &page_info, (DWORD) sizeof(PSAPI_WORKING_SET_EX_INFORMATION));
    printf("Function access in working set: %d, share count: %d\n", page_info.VirtualAttributes.Valid,
           page_info.VirtualAttributes.ShareCount);

    i++;

    Sleep(500);
  }
}

