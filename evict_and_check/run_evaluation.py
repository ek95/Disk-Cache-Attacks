#!/usr/bin/env python3.8
import sys
import os
import math
import subprocess
import threading
import signal
import numpy
from pathlib import Path

# require python 3.7 (dict insertion order preservation)
MIN_PYTHON = (3, 7)
if sys.version_info < MIN_PYTHON:
    sys.exit("Python %s.%s or later is required.\n" % MIN_PYTHON)


#-------------------------------------------------------------------------------
# GLOBALS
#-------------------------------------------------------------------------------

BUILD_SCRIPT_REL_PATH = Path("./build.sh")
EV_CHK_BINARY_REL_FOLDER = Path("./build/bin")
EV_CHK_BINARY = "ev_chk"
EV_CHK_CONF_FILE_REL_PATH = Path("./build/bin/eval.conf")
TARGET_FILE_REL_PATH = Path("./build/bin/test.so")
TARGET_PAGE = 1
ACCESS_BINARY_REL_PATH = Path("../tools/access/bin/access")
ACCESS_COUNT = 10
ACCESS_PERIOD_MS = 1000
LOG_REL_FOLDER = Path("./logs")
TRACE_NAME = Path("trace.csv")
EVALUATION_NAME = Path("evaluation.csv")
IOSTAT_RESULT_LOG_NAME = Path("iostat.log")


#-------------------------------------------------------------------------------
# MAIN SCRIPT
#-------------------------------------------------------------------------------

def evChkPipeWorker(args):
    for line in args["pipe"]:
        # print(line)
        if "Ready..." in line:
            args["ready_sem"].release()
        elif "Error" in line:
            args["ready_sem"].release()
    # always release if program ended
    args["ready_sem"].release()


# create test file
if not TARGET_FILE_REL_PATH.exists():
    subprocess.run(["dd",
                    "if=/dev/urandom",
                    "of=" + TARGET_FILE_REL_PATH,
                    "bs=1M",
                    "count=2"],
                   check=True)

# create log folder (if not exists)
if not LOG_REL_FOLDER.exists():
    os.makedirs(LOG_REL_FOLDER)

# instantiate build
subprocess.run(BUILD_SCRIPT_REL_PATH.resolve(), check=True)

# run eviction (not blocking)
ev_chk_p = subprocess.Popen([(EV_CHK_BINARY_REL_FOLDER / EV_CHK_BINARY).resolve(),
                             EV_CHK_CONF_FILE_REL_PATH.resolve(),
                             "-v"],
                            stdout=subprocess.PIPE,
                            universal_newlines=True,
                            bufsize=1,
                            cwd=EV_CHK_BINARY_REL_FOLDER.resolve())

# start stdout pipe listener thread
ev_chk_pipe_worker_args = {
    "pipe": ev_chk_p.stdout,
    "ready_sem": threading.Semaphore(0)
}
ev_chk_pipe_worker_t = threading.Thread(target=evChkPipeWorker,
                                        args=(ev_chk_pipe_worker_args,))
ev_chk_pipe_worker_t.start()

# wait until attack process is ready
ev_chk_pipe_worker_args["ready_sem"].acquire()
# check if attack binary ended prematurly (error)
ev_chk_p.poll()
if ev_chk_p.returncode is not None and ev_chk_p.returncode != 0:
    raise Exception("Error at executing attack!")
 # killall instances
os.system("killall " + EV_CHK_BINARY)

# run iostat (not blocking)
# assumes pipe buffer is big enough to receive output from iostat
# (should be the case, for linux 16 pages by default)
iostat_p = subprocess.Popen(["iostat", "-x", "-y", "-z",
                             str(math.floor(ACCESS_COUNT * ACCESS_PERIOD_MS / 1000)),
                             "1"],
                            stdout=subprocess.PIPE,
                            universal_newlines=True,
                            bufsize=1,)

# start access binary (blocking)
access_p = subprocess.run([ACCESS_BINARY_REL_PATH.resolve(),
                           TARGET_FILE_REL_PATH,
                           str(TARGET_PAGE),
                           str(ACCESS_PERIOD_MS),
                           str(ACCESS_COUNT)],
                          check=True)

# signal attack process to end
ev_chk_p.send_signal(signal.SIGINT)
# join ev_chk worker
ev_chk_pipe_worker_t.join()
# killall processes
ev_chk_p.kill()
# wait till attack process is closed
ev_chk_p.wait()
if ev_chk_p.returncode != 0:
    raise Exception("Error at executing attack!")
# wait till iostat process is closed
iostat_p.wait()


# save iostat results
iostat_f = open(LOG_REL_FOLDER / IOSTAT_RESULT_LOG_NAME, "w+")
iostat_f.write(iostat_p.stdout.read())
iostat_f.close()


# parse trace file
trace_data = numpy.genfromtxt(LOG_REL_FOLDER / TRACE_NAME,
                              delimiter=";", skip_header=3)

if trace_data.size == 0:
    print("No eviction was possible!")
else:
    # calculate mean, std
    eviction_time_mean = numpy.mean(trace_data[:, 2])
    eviction_time_std = numpy.sqrt(numpy.var(trace_data[:, 2]))

    # print evaluation results + save to file
    print("")
    print("Samples: " + str(len(trace_data[:, 2])))
    print("Eviction time mean [ns]: " + str(eviction_time_mean))
    print("Eviction time std [ns]: " + str(eviction_time_std))

    log_f = open(LOG_REL_FOLDER / EVALUATION_NAME, "w+")
    log_f.write("Samples;{}\n".format(len(trace_data[:, 2])))
    log_f.write("Eviction time mean [ns];{}\n".format(eviction_time_mean))
    log_f.write("Eviction time std [ns];{}\n".format(eviction_time_std))
    log_f.close()
