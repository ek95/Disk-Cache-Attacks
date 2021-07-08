#!/usr/bin/env python3.8
import struct
import math
import numpy as np
import argparse


BYTES_BITS_SET = [bin(b).count("1") for b in range(256)]


def bytesGetSetBits(bytes):
    set_bits = 0
    for byte in bytes:
        set_bits += BYTES_BITS_SET[byte]
    return set_bits

def bytesDiff(bytesA, bytesB):
    if len(bytesA) != len(bytesB):
        raise RuntimeError("Byte vectors do not have the same length!")
    
    bytesC = bytearray()
    for i in range(len(bytesA)):
        bytesC += (bytesA[i] ^ bytesB[i]).to_bytes(1, byteorder='big')
    
    return bytesC
    

parser = argparse.ArgumentParser(
    description="Evaluate covert channel trace files.")
parser.add_argument("snd_data_trace", type=str)
parser.add_argument("rcv_data_trace", type=str)
args = parser.parse_args()

# result statistics 
transmit_times_ns = []
bit_errors = []

# open trace files
snd_data_trace_file = open(args.snd_data_trace, "rb")
rcv_data_trace_file = open(args.rcv_data_trace, "rb")

# load data
msg_size_snd = struct.unpack("Q", snd_data_trace_file.read(8))[0]
msg_size_rcv = struct.unpack("Q", rcv_data_trace_file.read(8))[0] 
test_runs_snd = struct.unpack("Q", snd_data_trace_file.read(8))[0] 
test_runs_rcv = struct.unpack("Q", rcv_data_trace_file.read(8))[0]
if msg_size_snd != msg_size_rcv or test_runs_snd != test_runs_rcv:
    print("Send and receive configuration did not match!")
    exit(-1)
msg_size = msg_size_snd 
test_runs = test_runs_snd

print(test_runs)
for i in range(test_runs):
    transmit_time_ns = struct.unpack("Q", rcv_data_trace_file.read(8))[0] - struct.unpack("Q", snd_data_trace_file.read(8))[0]
    msg_diff = bytesDiff(rcv_data_trace_file.read(msg_size), snd_data_trace_file.read(msg_size))


    transmit_times_ns.append(transmit_time_ns)
    bit_errors.append(bytesGetSetBits(msg_diff))

# calculate statistics
transmit_times_ns = np.array(transmit_times_ns[1:])
bit_errors = np.array(bit_errors[1:])
transmit_speeds_bps = msg_size / transmit_times_ns * 1e9

transmit_speed_mean_bps = np.mean(transmit_speeds_bps)
transmit_speed_std_bps = np.sqrt(np.var(transmit_speeds_bps))
transmit_speed_std_percent = transmit_speed_std_bps / transmit_speed_mean_bps * 100

bit_errors_mean = np.mean(bit_errors)
bit_errors_std = np.sqrt(np.var(bit_errors))
bit_errors_std_percent = bit_errors_std / bit_errors_mean * 100

# print results
print("Transmit Speed Mean: {} +- {}({}%) bps".format(transmit_speed_mean_bps, transmit_speed_std_bps, transmit_speed_std_percent))
print("Bit Erros Mean: {} +- {}({}%)".format(bit_errors_mean, bit_errors_std, bit_errors_std_percent))

print(transmit_times_ns)
print(bit_errors)
print(transmit_speeds_bps)