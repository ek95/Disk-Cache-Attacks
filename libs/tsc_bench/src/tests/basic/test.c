#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include "tsc_bench.h"

int main(int argc, char *argv[])
{
    uint64_t start_cycle, stop_cycle;
    struct timespec start_time, stop_time;

    if(argc != 2) {
        printf("USAGE: %s <tsc frequency khz>\n", argv[0]);
        return -1;
    }

    if(tsc_bench_init(atoi(argv[1])) != 0) {
        printf("Error at tsc_bench initialization!\n");
        return -1;
    }

    // measurement with tsc bench library
    printf("\nMeasuring time of sleep(1) using tsc_bench:\n");
    for(size_t i = 0; i < 10; i++) {
        TSC_BENCH_START(start_cycle);
        sleep(1);
        TSC_BENCH_STOP(stop_cycle);
        printf("Took %lu ns\n", tsc_bench_get_runtime_ns(start_cycle, stop_cycle));
    }

    // for comparision measurement with clock_gettime
    // get approximate measurement overhead 
    // (not checked if measurement overhead is stable over differnt subpopultions)
    uint64_t clock_gettime_overhead_ns = UINT64_MAX;
    for(size_t i = 0; i < TSC_BENCH_INIT_SAMPLES; i++) {
        asm volatile("CPUID" : : : "rax", "rbx", "rcx", "rdx");
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        asm volatile("CPUID" : : : "rax", "rbx", "rcx", "rdx");
        asm volatile("CPUID" : : : "rax", "rbx", "rcx", "rdx");
        clock_gettime(CLOCK_MONOTONIC, &stop_time);
        asm volatile("CPUID" : : : "rax", "rbx", "rcx", "rdx");
        uint64_t runtime_ns = (stop_time.tv_sec - start_time.tv_sec) * 1000000000UL + 
            (stop_time.tv_nsec - start_time.tv_nsec);
        // save min value as measurement overhead
        if(runtime_ns < clock_gettime_overhead_ns) {
            clock_gettime_overhead_ns = runtime_ns;
        }
    }
    printf("Overhead of clock_gettime measurements: %lu ns", clock_gettime_overhead_ns);

    printf("\nMeasuring time of sleep(1) using clock_gettime:\n");
    for(size_t i = 0; i < 10; i++) {
        asm volatile("CPUID" : : : "rax", "rbx", "rcx", "rdx");
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        asm volatile("CPUID" : : : "rax", "rbx", "rcx", "rdx");
        sleep(1);
        asm volatile("CPUID" : : : "rax", "rbx", "rcx", "rdx");
        clock_gettime(CLOCK_MONOTONIC, &stop_time);
        asm volatile("CPUID" : : : "rax", "rbx", "rcx", "rdx");
        uint64_t runtime_ns = (stop_time.tv_sec - start_time.tv_sec) * 1000000000UL + 
            (stop_time.tv_nsec - start_time.tv_nsec) - clock_gettime_overhead_ns;
        printf("Took %lu ns\n", runtime_ns);
    }

    return 0;
} 
