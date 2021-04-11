#ifndef _TSC_BENCH_H_
#define _TSC_BENCH_H_

#include <stdio.h>
#include <stdint.h>
#ifdef __linux
    #include <sched.h>
#elif defined(_WIN32)
    #include <Windows.h>
#else 
    #error OS not supported!
#endif

// defines
#define TSC_BENCH_INIT_SAMPLES (100000LU)
#define TSC_BENCH_INIT_ENSEMBLES (100LU)
#define TSC_BENCH_LINUX_TSC_FREQ_SYS_PATH "/sys/devices/system/cpu/cpu0/tsc_freq_khz"

// macros
//#define TSC_BENCH_DEBUG
#ifdef TSC_BENCH_DEBUG
#define TSC_BENCH_PRINT(x) printf x
#else
#define TSC_BENCH_PRINT(x)\
    do\
    {\
    } while (0)
#endif

// detect target architecture
#if __GNUC__
    #ifdef __x86_64__
        #define ARCH_X64
    #endif
#else 
    #error Compiler not supported!
#endif


// tsc sample macros
#if defined(ARCH_X64)
    #if defined(__GNUC__)
        #define TSC_BENCH_START(x) asm volatile (   "CPUID\n\t"\
                                                    "RDTSC\n\t"\
                                                    "shl $32, %%rdx\n\t"\
                                                    "or %%rdx, %0\n\t"\
                                                    : "=a" (x) : : "rbx", "rcx", "rdx"\
                                                )
                                        
        #define TSC_BENCH_STOP(x) asm volatile  (   "RDTSCP\n\t"\
                                                    "shl $32, %%rdx\n\t"\
                                                    "or %%rdx, %%rax\n\t"\
                                                    "mov %%rax, %0\n\t"\
                                                    "CPUID\n\t"\
                                                    : "=r" (x) : : "rax", "rbx", "rcx", "rdx"\
                                                ) 
    #endif
#else
    #error Architecture not supported!
#endif


// functions
int tsc_bench_init(uint64_t tsc_frequency_khz);
uint64_t tsc_bench_get_runtime_ns(uint64_t start_cycle, uint64_t stop_cycle); 

#endif