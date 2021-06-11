#ifndef _OSAL_H_
#define _OSAL_H_

#ifdef __linux 
    #include <sys/types.h>  
    #include <semaphore.h>
    #include <signal.h>

    typedef pid_t osal_pid_t;


    static inline int osal_process_kill(osal_pid_t pid) {
        return kill(pid, SIGKILL);
    }
#elif defined(_WIN32)
    #include "windows.h"

    typedef HANDLE pid_t;


    static inline int osal_process_kill(osal_pid_t pid) {
      return TerminateProcess(pid, 0);
    }
#else 
  #error "Operating system not supported!"  
#endif

#endif