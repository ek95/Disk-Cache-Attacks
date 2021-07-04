#!/usr/bin/env python3.8
import sys
import os
import math
import random
import re
import subprocess
import threading
import signal
import time
import mmap
import shutil

# require python 3.7 (dict insertion order preservation)
MIN_PYTHON = (3, 7)
if sys.version_info < MIN_PYTHON:
    sys.exit("Python %s.%s or later is required.\n" % MIN_PYTHON)


#-------------------------------------------------------------------------------
# GLOBALS
#-------------------------------------------------------------------------------

CONFIG_DEFAULT_REL_PATH = "./src/config_default.h"
CONFIG_TEMPLATE_REL_PATH = "./src/config_template.h"
CONFIG_OUT_REL_PATH = "./src/config.h"
GRID_SAMPLE_RUNS = 200
EV_CHK_BINARY_REL_FOLDER = "./build/bin"
EV_CHK_BINARY = "ev_chk"
EV_CHK_CONF_FILE_REL_PATH = "./build/bin/eval.conf"
EV_CHK_CONF_FILE_TEMPLATE = "{}\n{} 0\n\n"
TARGET_FILE_REL_PATH = "./build/bin/test.so"
TARGET_PAGE = 1
ACCESS_BINARY_REL_PATH = "../tools/access/bin/access"
ACCESS_COUNT = 2
ACCESS_PERIOD_MS = 1000
LOG_REL_FOLDER = "./logs"
LOG_NAME = "parameters.csv"
IOSTAT_RESULT_LOG_NAME_TEMPLATE = "iostat_{}.log"
RUN_SLEEP_TIME_S = 30


#-------------------------------------------------------------------------------
# MAIN SCRIPT
#-------------------------------------------------------------------------------

def castData(data, type):
    if type == "integer":
        return int(data)
    elif type == "string":
        return str(data)
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

        if "post_sample_method" in value_conf:
            values[value_name] = value_conf["post_sample_method"](values[value_name], values)

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
        print(line)
        if "Ready..." in line:
            args["ready_sem"].release()
        elif "Mean time to eviction per hit:" in line:
            args["eviction_time_ns"] = float(line.split(":")[1].split(" ")[1])
    # always release if program ended
    args["ready_sem"].release()


grid_search_conf = {
    "USE_ATTACK_BS": {
        "data_type": "integer",
        "method": "fixed",
        "value": 1
    },
    "USE_ATTACK_WS": {
        "data_type": "integer",
        "method": "fixed",
        "value": 1
    },
    "USE_ATTACK_SS": {
        "data_type": "integer",
        "method": "fixed",
        "value": 0
    },
    "BS_FILLUP_SIZE": {
        "data_type": "integer",
        "method": "fixed",
        "value": 8 * 1024 * mmap.PAGESIZE
    },
    "BS_MIN_AVAILABLE_MEM": {
        "data_type": "integer",
        "method": "random_range",
        "min_value": 8 * 1024,
        "max_value": 1024 * 1024,
        "post_sample_method": lambda value, values: value * mmap.PAGESIZE
    },
    "BS_MAX_AVAILABLE_MEM": {
        "data_type": "integer",
        "method": "func",
        "function": lambda values: values["BS_MIN_AVAILABLE_MEM"] + 2*values["BS_FILLUP_SIZE"]
    },
    "BS_EVALUATION_SLEEP_TIME_US": {
        "data_type": "integer",
        "method": "random_range",
        "min_value": 0,
        "max_value": 100 * 1000,
    },
    "ES_USE_ANON_MEMORY": {
        "data_type": "integer",
        "method": "random_range",
        "min_value": 0,
        "max_value": 1
    },
    "ES_USE_ACCESS_THREADS": {
        "data_type": "integer",
        "method": "random_range",
        "min_value": 0,
        "max_value": 1  
    },
    "ES_USE_FILE_API": {
        "data_type": "integer",
        "method": "random_range",
        "min_value": 0,
        "max_value": 1,
        "post_sample_method": lambda value, values: 0 if values["ES_USE_ANON_MEMORY"] else value
    },
    "ES_TARGETS_CHECK_ALL_X_BYTES": {
        "data_type": "integer",
        "method": "random_range",
        "min_value": 1,
        "max_value": 64 * 1024,
        "post_sample_method": lambda value, values: value * mmap.PAGESIZE
    },
    "ES_WS_ACCESS_ALL_X_BYTES": {
        "data_type": "integer",
        "method": "random_range",
        "min_value": 0,
        "max_value": 64,
        "post_sample_method": lambda value, values: 0 if value == 0 else int((values["BS_MAX_AVAILABLE_MEM"] / mmap.PAGESIZE) / value) * mmap.PAGESIZE
    },
    "ES_SS_ACCESS_ALL_X_BYTES": {
        "data_type": "integer",
        "method": "random_range",
        "min_value": 0,
        "max_value": 64, 
        "post_sample_method": lambda value, values: 0 if value == 0 else int((values["BS_MAX_AVAILABLE_MEM"] / mmap.PAGESIZE) / value) * mmap.PAGESIZE
    },
    "ES_PREFETCH_ES_BYTES": {
        "data_type": "integer",
        "method": "random_range",
        "min_value": 0,
        "max_value": 1024,
        "post_sample_method": lambda value, values: value * mmap.PAGESIZE
    },
    "ES_ACCESS_THREAD_COUNT": {
        "data_type": "integer",
        "method": "random_range",
        "min_value": 1,
        "max_value": 100
    },
    "WS_EVALUATION": {
        "data_type": "integer",
        "method": "random_range",
        "min_value": 0,
        "max_value": 1  
    },
    "WS_EVICTION_IGNORE_EVALUATION": {
        "data_type": "integer",
        "method": "fixed",
        "value": 1
    },
    "WS_USE_FILE_API": {
        "data_type": "integer",
        "method": "random_range",
        "min_value": 0,
        "max_value": 1  
    },    
    "WS_PS_ADD_THRESHOLD": {
        "data_type": "integer",
        "method": "random_range",
        "min_value": 1,
        "max_value": 512
    },
    "WS_ACCESS_SLEEP_TIME_US": {
        "data_type": "integer",
        "method": "random_range",
        "min_value": 0,
        "max_value": 100 * 1000,
    },  
    "WS_EVALUATION_SLEEP_TIME_US": {
        "data_type": "integer",
        "method": "random_range",
        "min_value": 0,
        "max_value": 30 * 1000 * 1000,
    },        
    "WS_ACCESS_THREAD_COUNT": {
        "data_type": "integer",
        "method": "random_range",
        "min_value": 1,
        "max_value": 100
    },
    "SS_USE_FILE_API": {
        "data_type": "integer",
        "method": "random_range",
        "min_value": 0,
        "max_value": 1  
    },      
    "SS_ACCESS_SLEEP_TIME_US": {
        "data_type": "integer",
        "method": "random_range",
        "min_value": 0,
        "max_value": 100 * 1000,
    },          
    "SS_ACCESS_THREAD_COUNT": {
        "data_type": "integer",
        "method": "random_range",
        "min_value": 1,
        "max_value": 100
    }    
}

# initial build
shutil.copyfile(CONFIG_DEFAULT_REL_PATH, CONFIG_OUT_REL_PATH)
subprocess.run("./build.sh", check=True)

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

# create attack eval configuration 
with open(EV_CHK_CONF_FILE_REL_PATH, "w") as file:
    file.write(EV_CHK_CONF_FILE_TEMPLATE.format(os.path.abspath(TARGET_FILE_REL_PATH), TARGET_PAGE))

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
                                 os.path.abspath(EV_CHK_CONF_FILE_REL_PATH),
                                 "-v"],
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

    # wait for reestablishment of working set
    time.sleep(RUN_SLEEP_TIME_S)

log_f.close()
