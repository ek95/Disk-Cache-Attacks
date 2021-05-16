cmake_minimum_required(VERSION 3.10)

project(touchadvise C)

set(CMAKE_C_STANDARD 99)
# default to release build
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# release flags
set(CMAKE_CXX_FLAGS_RELEASE_INIT "-O3 -Wall -Wunused -Wpedantic")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE_INIT "-s")

# debug flags
set(CMAKE_CXX_FLAGS_DEBUG_INIT "-g -fsanitize=address -fsanitize=thread -Wall -Wunused -Wpedantic")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG_INIT "-fsanitize=address -fsanitize=thread")

# custom output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# external libs
include_directories(../../../libs/filemap/src)
add_subdirectory(../../../libs/filemap lib/filemap)

# main project
add_subdirectory(src)
