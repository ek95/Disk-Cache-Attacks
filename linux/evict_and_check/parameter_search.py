#!/usr/bin/env python3.8
import sys
import os
import math
import random
import re
import subprocess
import threading
import signal

# require python 3.7 (dict insertion order preservation)
MIN_PYTHON = (3, 7)
if sys.version_info < MIN_PYTHON:
    sys.exit("Python %s.%s or later is required.\n" % MIN_PYTHON)


#-------------------------------------------------------------------------------
# GLOBALS
#-------------------------------------------------------------------------------

CONFIG_TEMPLATE_REL_PATH = "./src/config_template.h"
CONFIG_OUT_REL_PATH = "./src/config.h"
GRID_SAMPLE_RUNS = 2
EV_CHK_BINARY_REL_FOLDER = "./build/bin"
EV_CHK_BINARY = "ev_chk"
TARGET_FILE_REL_PATH = "./build/bin/test.so"
TARGET_PAGE = 1
ACCESS_BINARY_REL_PATH = "../tools/access/bin/access"
ACCESS_COUNT = 25
ACCESS_PERIOD_MS = 1000
LOG_REL_FOLDER = "./logs"
LOG_NAME = "parameters.csv"
IOSTAT_RESULT_LOG_NAME_TEMPLATE = "iostat_{}.log"


#-------------------------------------------------------------------------------
# MAIN SCRIPT
#-------------------------------------------------------------------------------

def castData(data, type):
    if type == "integer":
        return int(data)
    else:
        raise NotImplementedError


def randomGridSample(grid_search_conf):
    values = {}
    for value_name in grid_search_conf:
        value_conf = grid_search_conf[value_name]
        if value_conf["method"] == "fixed":
            values[value_name] = castData(value_conf["value"],
                                          value_conf["data_type"])
        elif (value_conf["method"] == "random_range" and
              value_conf["data_type"] == "integer"):
            values[value_name] = castData(random.randint(value_conf["min_value"],
                                                         value_conf["max_value"]),
                                                         value_conf["data_type"])
        elif value_conf["method"] == "func":
            values[value_name] = castData(value_conf["function"](values),
                                          value_conf["data_type"])
        else:
            raise NotImplementedError

    return values


def writeConfig(values_config, values, config_template):
    config = config_template
    for value_name in values:
        value_string = str(values[value_name])
        if values_config[value_name]["data_type"] == "integer":
            value_string += "ULL"

        config = re.sub(r"/\*" + value_name + r"\*/", value_string, config)

    config_f = open(CONFIG_OUT_REL_PATH, "w+")
    config_f.write(config)
    config_f.close()


def evChkPipeWorker(args):
    for line in args["pipe"]:
        if "Ready..." in line:
            args["ready_sem"].release()
        elif "Mean time to eviction per event:" in line:
            args["eviction_time_ns"] = float(line.split(":")[1].split(" ")[1])
    # always release if program ended
    args["ready_sem"].release()


def calcWsAccessThreadsPerPu(data):
    available_pus = os.cpu_count()
    useable_pus = int(available_pus / data["PU_INCREASE"] - 2)
    access_threads_per_pu = math.ceil(data["WS_ACCESS_THREAD_COUNT"] / useable_pus)
    # update actual value of access thread count
    data["WS_ACCESS_THREAD_COUNT"] = access_threads_per_pu * useable_pus
    return access_threads_per_pu


def calcBsMaxAvailableMem(data):
    return data["BS_MIN_AVAILABLE_MEM"] + 2 * data["BS_FILLUP_SIZE"]


grid_search_conf = {
    "PU_INCREASE": {
        "data_type": "integer",
        "method": "fixed",
        "value": 1
    },
    "USE_ATTACK_WS": {
        "data_type": "integer",
        "method": "fixed",
        "value": 1
    },
    "USE_ATTACK_BS": {
        "data_type": "integer",
        "method": "fixed",
        "value": 1
    },
    "WS_PS_ADD_THRESHOLD": {
        "data_type": "integer",
        "method": "random_range",
        "min_value": 1,
        "max_value": 32
    },
    "WS_ACCESS_THREAD_COUNT": {
        "data_type": "integer",
        "method": "random_range",
        "min_value": 1,
        "max_value": 100
    },
    "WS_ACCESS_THREADS_PER_PU": {
        "data_type": "integer",
        "method": "func",
        "function": calcWsAccessThreadsPerPu
    },
    "WS_ACCESS_SLEEP_TIME_NS": {
        "data_type": "integer",
        "method": "random_range",
        "min_value": 1000000,
        "max_value": 999999999
    },
    "WS_ACCESS_SLEEP_TIME_S": {
        "data_type": "integer",
        "method": "fixed",
        "value": 0
    },
    "WS_EVALUATION": {
        "data_type": "integer",
        "method": "fixed",
        "value": 1
    },
    "WS_EVICTION_IGNORE_EVALUATION": {
        "data_type": "integer",
        "method": "random_range",
        "min_value": 0,
        "max_value": 1
    },
    "WS_EVALUATION_SLEEP_TIME_NS": {
        "data_type": "integer",
        "method": "random_range",
        "min_value": 1000000,
        "max_value": 999999999
    },
    "WS_EVALUATION_SLEEP_TIME_S": {
        "data_type": "integer",
        "method": "random_range",
        "min_value": 0,
        "max_value": 5
    },
    "BS_FILLUP_SIZE": {
        "data_type": "integer",
        "method": "fixed",
        "value": 16*1024*1024
    },
    "BS_MIN_AVAILABLE_MEM": {
        "data_type": "integer",
        "method": "random_range",
        "min_value": 128*1024*1024,
        "max_value": 1*1024*1024*1024
    },
    "BS_MAX_AVAILABLE_MEM": {
        "data_type": "integer",
        "method": "func",
        "function": calcBsMaxAvailableMem
    },
    "BS_EVALUATION_SLEEP_TIME_NS": {
        "data_type": "integer",
        "method": "random_range",
        "min_value": 1000000,
        "max_value": 999999999
    },
    "BS_EVALUATION_SLEEP_TIME_S": {
        "data_type": "integer",
        "method": "random_range",
        "min_value": 0,
        "max_value": 5
    },
}

# read config template file
config_template_f = open(CONFIG_TEMPLATE_REL_PATH, "r")
config_template = config_template_f.read()
config_template_f.close()

# create test file
if not os.path.exists(TARGET_FILE_REL_PATH):
    subprocess.run(["dd",
                    "if=/dev/urandom",
                    "of=" + TARGET_FILE_REL_PATH,
                    "bs=1M",
                    "count=2"],
                   check=True)

# create log folder (if not exists)
if not os.path.exists(LOG_REL_FOLDER):
    os.makedirs(LOG_REL_FOLDER)

# create log file
log_f = open(LOG_REL_FOLDER + "/" + LOG_NAME, "w+")
log_f.write(";".join(grid_search_conf.keys()) + "; Eviction Time [ns]\n")

for r in range(GRID_SAMPLE_RUNS):
    print("\nRun " + str(r))

    # sample values
    values = randomGridSample(grid_search_conf)
    # write new config
    writeConfig(grid_search_conf, values, config_template)
    # instantiate build
    subprocess.run("./build.sh", check=True)

    # run eviction (not blocking)
    ev_chk_p = subprocess.Popen(["./" + EV_CHK_BINARY,
                                 os.path.abspath(TARGET_FILE_REL_PATH),
                                 str(TARGET_PAGE)],
                                stdout=subprocess.PIPE,
                                universal_newlines=True,
                                bufsize=1,
                                cwd=EV_CHK_BINARY_REL_FOLDER)

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
    access_p = subprocess.run([ACCESS_BINARY_REL_PATH,
                               TARGET_FILE_REL_PATH,
                               str(TARGET_PAGE),
                               str(ACCESS_PERIOD_MS),
                               str(ACCESS_COUNT)],
                              check=True)

    # signal attack process to end
    ev_chk_p.send_signal(signal.SIGINT)
    # join ev_chk worker
    ev_chk_pipe_worker_t.join()
    # wait till attack process is closed
    ev_chk_p.wait()
    if ev_chk_p.returncode != 0:
        raise Exception("Error at executing attack!")
    # wait till iostat process is closed
    iostat_p.wait()

    # save grid evaluation results
    log_f.write(";".join([str(v) for v in values.values()]) + ";" +
                str(ev_chk_pipe_worker_args["eviction_time_ns"]) + "\n")

    # save iostat results
    iostat_f = open(LOG_REL_FOLDER + "/" +
                    IOSTAT_RESULT_LOG_NAME_TEMPLATE.format(r + 2), "w+")
    iostat_f.write(iostat_p.stdout.read())
    iostat_f.close()

log_f.close()
