#ifndef _OSAL_H_
#define _OSAL_H_

#ifdef __linux 
    #include <sys/types.h>  
    #include <semaphore.h>
    #include <signal.h>
    #include <errno.h>


    #define OSAL_MAX_PATH_LEN PATH_MAX
    #define OSAL_EC_FS "(errno: %d)" 
    #define OSAL_EC errno


    typedef pid_t osal_pid_t;


    static inline int osal_process_kill(osal_pid_t pid) 
    {
        return kill(pid, SIGKILL);
    }

    static inline char* osal_fullpath(char *rel_path, char *abs_path) 
    {
        return realpath(rel_path, abs_path, PATH_MAX);
    }

    static char* osal_get_system_error_str() 
    {
        return strerror(errno);
    }
#elif defined(_WIN32)
    #include "windows.h"


    #define OSAL_MAX_PATH_LEN MAX_PATH
    #define OSAL_EC_FS "(errno: %d, GetLastError: %d)" 
    #define OSAL_EC errno, GetLastError() 


    typedef HANDLE pid_t;


    static inline int osal_process_kill(osal_pid_t pid) 
    {
      return TerminateProcess(pid, 0);
    }

    static inline char* osal_fullpath(char *rel_path, char *abs_path) 
    {
        return _fullpath(abs_path, rel_path, MAX_PATH);
    }

    static char* osal_get_system_error_str() 
    {
        return strerror(errno);
    }
#else 
  #error "Operating system not supported!"  
#endif

#endif