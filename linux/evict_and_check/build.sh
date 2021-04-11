#!/usr/bin/env bash

# parse arguments
BUILD_TYPE=${1:-Release}

# out-of-source build

# cmake < 3.13
cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE -B./build -H.
# cmake >= 3.13
# cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE -B./build -S.

cd build
make