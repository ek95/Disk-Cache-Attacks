#ifndef _OSAL_H_
#define _OSAL_H_

#ifdef __linux 
    #include <sys/types.h>  
    #include <sys/time.h>
    #include <sys/random.h>
    #include <semaphore.h>
    #include <signal.h>
    #include <errno.h>
    #include <linux/limits.h>
    #include <sched.h> 
    #include <time.h>
    #include <unistd.h>


    #define OSAL_MAX_PATH_LEN PATH_MAX
    #define OSAL_EC_FS "(errno: %d)" 
    #define OSAL_EC errno
    #define OSAL_PID_INVALID -1


    typedef pid_t osal_pid_t;


    static inline int osal_process_kill(osal_pid_t pid) 
    {
        return kill(pid, SIGKILL);
    }

    static inline char* osal_fullpath(char *rel_path, char *abs_path) 
    {
        return realpath(rel_path, abs_path);
    }
    
    static inline size_t osal_unix_ts_us() 
    {
        struct timeval tv = {0};
        gettimeofday(&tv, NULL);
        return tv.tv_sec * 1000000UL + tv.tv_usec; 
    }

    static inline void osal_sched_yield()
    {
        sched_yield();
    }

    static inline void osal_sleep_us(size_t microseconds)
    {
        struct timespec wait_time = {
            .tv_sec = microseconds / 1000000ULL,
            .tv_nsec = (microseconds % 1000000ULL) * 1000ULL
        };
        nanosleep(&wait_time, NULL);
    }

    static inline size_t osal_get_page_size()
    {
        // get system page size
        return sysconf(_SC_PAGESIZE);
    }

    static inline ssize_t osal_get_random(uint8_t *buf, size_t len) 
    {
        return getrandom(buf, len, 0);
    }

    static inline size_t osal_get_timestamp_ns() 
    {
        struct timespec ts = {0};
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return ts.tv_sec * 1000000000ULL + ts.tv_nsec; 
    }
#elif defined(_WIN32)
    #include "windows.h"


    #define OSAL_MAX_PATH_LEN MAX_PATH
    #define OSAL_EC_FS "(errno: %d, GetLastError: %d)" 
    #define OSAL_EC errno, GetLastError() 
    #define OSAL_PID_INVALID INVALID_HANDLE_VALUE


    typedef HANDLE osal_pid_t;


    static inline int osal_process_kill(osal_pid_t pid) 
    {
      return TerminateProcess(pid, 0);
    }

    static inline char* osal_fullpath(char *rel_path, char *abs_path) 
    {
        return _fullpath(abs_path, rel_path, MAX_PATH);
    }

    static inline size_t osal_unix_ts_us() 
    {
        FILETIME file_time;
        LARGE_INTEGER file_time_interger;

        // utc in 100ns ticks
        GetSystemTimeAsFileTime(&file_time); 
        file_time_interger.LowPart  = file_time.dwLowDateTime;
        file_time_interger.HighPart = file_time.dwHighDateTime;
        
        // to unix timestamp in us resolution
        return li.QuadPart / 10 - 116444736000000000000ULL;
    }

    static inline void osal_sched_yield()
    {
        SwitchToThread();
    }

    static inline void osal_sleep_us(size_t microseconds)
    {
        // windows can only sleep for ms
        Sleep(microseconds / 1000);
    }

    static inline size_t osal_get_page_size()
    {
        // get system page size
        SYSTEM_INFO system_info;
        GetSystemInfo(&system_info);
        return system_info.dwPageSize;
    }

    static inline ssize_t osal_get_random(uint8_t *buf, size_t len) 
    {
        if(BCryptGenRandom(NULL, (BYTE *) buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS)
        {
            return -1;
        }
        return len;
    }

    static inline size_t osal_get_timestamp_ns() 
    {

    }
#else 
  #error "Operating system not supported!"  
#endif

#endif