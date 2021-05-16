cmake_minimum_required(VERSION 3.10)

project(filemap C)

set(CMAKE_C_STANDARD 99)

# release flags
set(CMAKE_C_FLAGS_RELEASE "-O3 -Wall -Wunused -Wpedantic")
set(CMAKE_EXE_LINKER_FLAGS_RELEASET "-s")
# debuginfo flags 
set(CMAKE_C_FLAGS_DEBUGINFO "-g3 -Wall -Wunused -Wpedantic")
# debug flags
set(CMAKE_C_FLAGS_DEBUG"-g -fsanitize=address -fsanitize=thread -Wall -Wunused -Wpedantic")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-fsanitize=address -fsanitize=thread")

# default to release build
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# custom output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# external libs
include_directories(../tsc_bench/src)
add_subdirectory(../tsc_bench lib/tsc_bench)

# enable ctest
enable_testing()

include_directories(src)
add_subdirectory(src)

