cmake_minimum_required(VERSION 3.10)

project(tsc_bench)

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  # release flags 
  set(CMAKE_C_FLAGS_RELEASE "-O3 -Wall -Wunused -Wpedantic")
  set(CMAKE_EXE_LINKER_FLAGS_RELEASE "-s")
  # debuginfo flags 
  set(CMAKE_C_FLAGS_DEBUGINFO "-g3 -Wall -Wunused -Wpedantic")
  # debug flags 
  set(CMAKE_C_FLAGS_DEBUG "-g -fsanitize=address -Wall -Wunused -Wpedantic")
  set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-fsanitize=address")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  # release flags 
  set(CMAKE_C_FLAGS_RELEASE "/O2 /W4")
  # debuginfo flags 
  set(CMAKE_C_FLAGS_DEBUGINFO "/Zi /DEBUG /W4")
  # debug flags 
  set(CMAKE_C_FLAGS_DEBUG "/Zi /DEBUG /W4")
endif()

# default to release build
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# custom output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  # enable ctest
  enable_testing()
endif()

# main project
include_directories(src)
add_subdirectory(src)
