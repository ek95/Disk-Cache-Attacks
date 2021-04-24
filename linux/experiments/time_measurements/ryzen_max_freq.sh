#!/bin/bash

echo "Run as root"
echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
echo 3600000 | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_min_freq
echo 3600000 | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_max_freq
