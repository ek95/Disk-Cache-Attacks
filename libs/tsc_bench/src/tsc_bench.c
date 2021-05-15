#include "tsc_bench.h"
#include <stdlib.h>
#include <inttypes.h>


#define ABS_DIFF(x, y) ((x) > (y) ? (x) - (y) : (y) - (x))


static uint64_t tsc_bench_overhead_cycles = 0;
static uint64_t tsc_bench_tsc_frequency_khz = 0;


static uint64_t get_min(uint64_t *samples, size_t count);
static uint64_t calc_mean(uint64_t *samples, size_t count);
static uint64_t calc_var(uint64_t *samples, size_t count);
static uint64_t auto_determine_tsc_freq();


// evaluate measurement overhead + stability of measurements
// NOTE the tsc_frequency used here should be calibrated already
//      if 0 is supplied, it is tried to fetch the tsc frequency value from the kernel
int tsc_bench_init(uint64_t tsc_frequency_khz) {
    int ret = 0;
    uint64_t start_cycle;
    uint64_t stop_cycle;
    uint64_t variance_variances;
    uint64_t variance_min_values;

    // clear current overhead value
    tsc_bench_overhead_cycles = 0;
    
    if(tsc_frequency_khz == 0) {
        tsc_bench_tsc_frequency_khz = auto_determine_tsc_freq();
        // could not auto determine frequency, return
        if(tsc_bench_tsc_frequency_khz == 0) {
            TSC_BENCH_PRINT(("Could not auto determine tsc frequency!\n"));
            return -1;
        }
    }
    else {
        // save tsc frequency
        tsc_bench_tsc_frequency_khz = tsc_frequency_khz;
    }

    uint64_t *samples = malloc(TSC_BENCH_INIT_SAMPLES * sizeof(uint64_t));
    uint64_t *variances = malloc(TSC_BENCH_INIT_ENSEMBLES * sizeof(uint64_t));
    uint64_t *min_values = malloc(TSC_BENCH_INIT_ENSEMBLES * sizeof(uint64_t));
    if(samples == NULL || variances == NULL || min_values == NULL) {
        ret = -1;
        goto cleanup;
    }

    // measure overhead
    for(size_t e = 0; e < TSC_BENCH_INIT_ENSEMBLES; e++) {
        for(size_t s = 0; s < TSC_BENCH_INIT_SAMPLES; s++) {
        // yield execution
        #ifdef __linux
            sched_yield();
        #elif defined(_WIN32)
            SwitchToThread();
        #endif

            TSC_BENCH_START(start_cycle);
            TSC_BENCH_STOP(stop_cycle);
            uint64_t delta = stop_cycle - start_cycle;
            samples[s] = delta;
        }

        // get variance
        variances[e] = calc_var(samples, TSC_BENCH_INIT_SAMPLES);
        // overflow
        if(variances[e] == (uint64_t) -1) {
            ret = -1;
            goto cleanup;
        }
        // get min value 
        min_values[e] = get_min(samples, TSC_BENCH_INIT_SAMPLES);

        TSC_BENCH_PRINT(("Ensemble %zu, sample count %lu: Var=%lu Min=%lu\n", e, TSC_BENCH_INIT_SAMPLES, variances[e], min_values[e]));
    }

    // get variance
    variance_variances = calc_var(variances, TSC_BENCH_INIT_ENSEMBLES);
    // overflow
    if(variance_variances == (uint64_t) -1) {
        ret = -1;
        goto cleanup;
    }
    // get variance
    variance_min_values = calc_var(min_values, TSC_BENCH_INIT_ENSEMBLES);
    // overflow
    if(variance_min_values == (uint64_t) -1) {
        ret = -1;
        goto cleanup;
    }

    TSC_BENCH_PRINT(("Variance of variances accross ensembles: %zu \n", variance_variances));
    TSC_BENCH_PRINT(("Variance of min values accross ensembles: %zu \n", variance_min_values));

    // check if minimum needed time (e.g. the min. measurment overhead is stable)
    if(variance_min_values != 0) {
        ret = -1;
        goto cleanup;
    }

    // save overhead
    tsc_bench_overhead_cycles = min_values[0];

cleanup:
    free(samples);
    free(variances);
    free(min_values);
    return ret;
}

uint64_t tsc_bench_get_runtime_ns(uint64_t start_cycle, uint64_t stop_cycle) {
    return (stop_cycle - start_cycle - tsc_bench_overhead_cycles) * 1000000UL / tsc_bench_tsc_frequency_khz;
}

static uint64_t get_min(uint64_t *samples, size_t count)
{
    uint64_t min = samples[0];
    for(size_t i = 1; i < count; i++) {
        if(samples[i] < min) {
            min = samples[i];
        }
    }

    return min;
}

static uint64_t calc_mean(uint64_t *samples, size_t count)
{
    uint64_t sum = 0;
    for(size_t i = 0; i < count; i++) {
        // overflow detection
        if(sum > (UINT64_MAX - samples[i])) {
            goto overflow;
        }
        sum += samples[i];
    }
    // rounds always done -> max error 1LSB
    return sum / count;

overflow:
    return (uint64_t) -1;
}

static uint64_t calc_var(uint64_t *samples, size_t count)
{
    uint64_t mean = calc_mean(samples, count);
    if(mean == (uint64_t) -1) {
        goto overflow;
    }

    uint64_t quad_diff_sum = 0;
    for(size_t i = 0; i < count; i++) {
        uint64_t abs_diff = ABS_DIFF(samples[i], mean);
        
        // overflow detection
        if(abs_diff > UINT64_MAX / abs_diff) {
            goto overflow;
        }
        uint64_t quad_diff = abs_diff * abs_diff;

        // overflow detection
        if(quad_diff_sum > UINT64_MAX - quad_diff) {
            goto overflow;
        }
        quad_diff_sum += quad_diff;
    }
    // rounds always done -> max error 1LSB
    return quad_diff_sum / count;

overflow:
    return (uint64_t) -1;   
}

static uint64_t auto_determine_tsc_freq() {
    uint64_t tsc_freq = 0;
#ifdef __linux
    FILE *file = fopen(TSC_BENCH_LINUX_TSC_FREQ_SYS_PATH, "r");
    if(file == NULL) {
        goto exit;
    }
    fscanf(file, "%" PRIu64, &tsc_freq);
    fclose(file);
#else 
    #error Not supported!
#endif

exit:
    return tsc_freq;
}

