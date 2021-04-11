#!/usr/bin/env python3

import numpy as np
import sys


# GLOBALS
# 1ms
MAX_MEAS_TIME_NS = 1000000      


# FUNCTIONS
def getPercentile(data, percentile):
    sum = 0
    data_percentile_max = 0
    hist = np.histogram(data, range = (0, MAX_MEAS_TIME_NS), bins = MAX_MEAS_TIME_NS + 1)[0]
    for hist_i in range(hist.shape[0]):
        sum += hist[hist_i]
        if sum / data.shape[0] * 100 >= percentile:
            data_percentile_max = hist_i
            break
    return data[data <= data_percentile_max]


if len(sys.argv) != 2:
    print("USAGE: {} <meas file>".format(sys.argv[0]))
    sys.exit(-1)

# read data
data = np.genfromtxt(sys.argv[1], delimiter = ';', skip_header = 1)

# calculate overhead mean + var
overhead_data = getPercentile(data[:, 0], 80)
overhead_mean = np.mean(overhead_data)
overhead_var = np.var(overhead_data)
overhead_std = np.sqrt(overhead_var)

# calculate target mean + var
target_data = getPercentile(data[:, 1], 90)
target_mean = np.mean(target_data)
target_var = np.var(target_data)
target_std = np.sqrt(target_var)

print("Sample size: " + str(data.shape[0]))
print("")
print("Overhead Mean [ns]: " + str(overhead_mean))
print("Overhead Standard Deviation [ns]: " + str(overhead_std))
print("")
print("Target Mean [ns]: " + str(target_mean))
print("Target Standard Deviation [ns]: " + str(target_std))
print("")
print("Target Mean Corrected [ns]: " + str(target_mean - overhead_mean))
print("Target Standard Deviation Corrected [ns]: " + str(np.sqrt(overhead_var + target_var)))