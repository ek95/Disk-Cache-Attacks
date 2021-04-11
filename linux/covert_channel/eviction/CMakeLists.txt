cmake_minimum_required(VERSION 3.10)

project(covert_channel C)

set(CMAKE_C_STANDARD 99)

# release flags 
set(CMAKE_C_FLAGS_RELEASE "-O3 -Wall -Wunused -Wpedantic")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE "-s")
# debuginfo flags 
set(CMAKE_C_FLAGS_DEBUGINFO "-g3 -Wall -Wunused -Wpedantic")
# debug flags 
set(CMAKE_C_FLAGS_DEBUG "-g -fno-omit-frame-pointer -fsanitize=address -Wall -Wunused -Wpedantic")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-fsanitize=address")

# default to release build
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# custom output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# enable ctest
enable_testing()

# external libs
include_directories(../../libs/cmdline/src)
add_subdirectory(../../libs/cmdline lib/cmdline)
include_directories(../../libs/dynarray/src)
add_subdirectory(../../libs/dynarray lib/dynarray)
include_directories(../../libs/list/src)
add_subdirectory(../../libs/list lib/list)
#include_directories(../../libs/pageflags/src)
#add_subdirectory(../../libs/pageflags lib/pageflags)
include_directories(../../libs/filemap/src)
add_subdirectory(../../libs/filemap lib/filemap)

# main project
add_subdirectory(src)
