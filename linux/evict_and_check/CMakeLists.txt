cmake_minimum_required(VERSION 3.10)

project(ev_chk C)

set(CMAKE_C_STANDARD 99)
# default to release build
set(CMAKE_BUILD_Release)

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

# enable ctest
enable_testing()

INCLUDE_DIRECTORIES(src)
add_subdirectory(src)
