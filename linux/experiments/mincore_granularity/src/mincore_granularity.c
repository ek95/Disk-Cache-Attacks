#define _GNU_SOURCE             /* See feature_test_macros(7) */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sched.h>
#include <sys/mman.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "filemap.h"
#include "tsc_bench.h"


#define MODE_ARG 1
#define TARGET_FILE_ARG 2
#define TARGET_PAGE_ARG 3
#define MEAS_FILE_ARG 4
#define ARG_COUNT (MEAS_FILE_ARG + 1)

#define RUNS_OVERHEAD 1000000UL
#define RUNS 10000000UL

#define USE_CLOCK_GETTIME

	
size_t PAGE_SIZE = 0;


int main(int argc, char *argv[]) {
	int ret = 0;
	int mode = 0;
	FileMapping target_mapping;
	size_t target_page = 0;
	void *addr = NULL;
	FILE *meas_file = NULL;
	volatile uint8_t tmp = 0;
	unsigned char page_status = 0;
#ifdef USE_CLOCK_GETTIME
	struct timespec start, stop;
#else 
	size_t cycles_start, cycles_end;
#endif 
	size_t sum_time_ns = 0;
	size_t *run_time_target_ns = NULL;
	size_t time_ns = 0;
	(void) addr;
	(void) tmp;
	

	// init file mapping
	initFileMapping(&target_mapping);


	if(argc != ARG_COUNT) {
		printf("USAGE: %s <mode> <target file> <target_page> <meas file>\n", argv[0]);
		return -1;
	}

	mode = atoi(argv[MODE_ARG]);
	target_page = strtoul(argv[TARGET_PAGE_ARG], NULL, 10);


	// get system page size
	PAGE_SIZE = sysconf(_SC_PAGESIZE);
	if(PAGE_SIZE == -1)
	{
		printf("Error (%s) at sysconf\n", strerror(errno));
		goto error;
	}


#ifdef USE_CLOCK_GETTIME
	size_t timing_overhead = -1;

	for(size_t r=0; r < RUNS_OVERHEAD; r++)
	{
		// clock_gettime version
		// serialize (out of order execution)
		asm volatile("CPUID\n\t" : : : "rbx", "rdx", "rcx");
		clock_gettime(CLOCK_MONOTONIC, &start);
		asm volatile("CPUID\n\t" : : : "rbx", "rdx", "rcx");
		asm volatile("CPUID\n\t" : : : "rbx", "rdx", "rcx");
		clock_gettime(CLOCK_MONOTONIC, &stop);
		asm volatile("CPUID\n\t" : : : "rbx", "rdx", "rcx");
		
		time_ns = (stop.tv_sec - start.tv_sec) * 1000000000UL + (stop.tv_nsec - start.tv_nsec);
		if(time_ns < timing_overhead) {
			timing_overhead = time_ns;
		}
		sched_yield();
	}
	printf("Measurement overhead %zu ns\n", timing_overhead);
#else 
	if(tsc_bench_init(0) != 0) {
		printf("Error at tsc_bench_init\n");
		goto error;
	}
#endif


	// allocate measurement array
	run_time_target_ns = malloc(RUNS * sizeof(size_t));
	if(run_time_target_ns == NULL) {
		printf("Error (%s) at malloc...\n", strerror(errno));
		goto error;
	}
	

	// map target
	if (mapFile(&target_mapping, argv[TARGET_FILE_ARG], O_RDONLY, PROT_READ /*| PROT_EXEC*/, MAP_PRIVATE) != 0) {
        printf("Error (%s) at mapFile for: %s ...\n", strerror(errno), argv[TARGET_FILE_ARG]);
        goto error;
    }
	if(target_page > target_mapping.size_pages_) {
		printf("Target page out of bounds....\n");
		goto error;
	}
	addr = (uint8_t *) target_mapping.addr_ + target_page * PAGE_SIZE;


	meas_file = fopen(argv[MEAS_FILE_ARG], "w");
	if(meas_file == NULL) {
		printf("Error (%s) at fopen...\n", strerror(errno));
		goto error;
	}
		

	if(mode == 0) {
		printf("Flushing target page...\n");
		page_status = 0;
		do {
			posix_fadvise(target_mapping.fd_, target_page * PAGE_SIZE, PAGE_SIZE, POSIX_FADV_DONTNEED);
			madvise(target_mapping.addr_, target_mapping.size_, MADV_DONTNEED);
			sched_yield();
			mincore(addr, PAGE_SIZE, &page_status);
		} while(page_status & 1);
		printf("Done...\n");
	}
	else if(mode == 1) {
		printf("Accessing target page...\n");
		page_status = 0;
		do {
			tmp = *((uint8_t *) addr);
			sched_yield();
			mincore(addr, PAGE_SIZE, &page_status);
		} while(!(page_status & 1));
		printf("Done...\n");
	}

	sum_time_ns = 0;
	for(size_t r=0; r < RUNS; r++)
	{		
#ifdef USE_CLOCK_GETTIME		
		// clock_gettime version
		// serialize (out of order execution)
		asm volatile("CPUID\n\t" : : : "rbx", "rdx", "rcx");
		clock_gettime(CLOCK_MONOTONIC, &start);
		asm volatile("CPUID\n\t" : : : "rbx", "rdx", "rcx");
		ret = mincore(addr, PAGE_SIZE, &page_status);
		asm volatile("CPUID\n\t" : : : "rbx", "rdx", "rcx");
		clock_gettime(CLOCK_MONOTONIC, &stop);
		asm volatile("CPUID\n\t" : : : "rbx", "rdx", "rcx");
		
		time_ns = (stop.tv_sec - start.tv_sec) * 1000000000UL + (stop.tv_nsec - start.tv_nsec) - timing_overhead;
#else	
		// tsc version
		TSC_BENCH_START(cycles_start);
		ret = mincore(addr, PAGE_SIZE, &page_status);
		TSC_BENCH_STOP(cycles_end);
		
		time_ns = tsc_bench_get_runtime_ns(cycles_start, cycles_end);
#endif	
		
		//fprintf(meas_file, "%zu\n", time_ns);
		run_time_target_ns[r] = time_ns;
		sum_time_ns += time_ns;
		sched_yield();
	}
	printf("Average runtime of mincore %zu ns\n", sum_time_ns / RUNS);
	

	if(fprintf(meas_file, "Time [ns]\n") < 0)
	{
		printf("Error (%s) at fprintf...\n", strerror(errno));
		goto error;
	}
	for(size_t r=0; r < RUNS; r++) {
		if(fprintf(meas_file, "%zu\n", run_time_target_ns[r]) < 0)
		{
			printf("Error (%s) at fprintf...\n", strerror(errno));
			goto error;
		}
	}
	
	goto cleanup;
error:
	ret = -1;

cleanup:
	
	if(meas_file != NULL)
	{
		fclose(meas_file);
	}
	closeFileMapping(&target_mapping);
	free(run_time_target_ns);
	
	return ret;
}
