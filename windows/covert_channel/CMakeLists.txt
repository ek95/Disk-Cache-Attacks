cmake_minimum_required(VERSION 3.10)
project(covert C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_BUILD_TYPE Debug)
if(CMAKE_COMPILER_IS_GNUCXX)
    set(CMAKE_EXE_LINKER_FLAGS "-s")  ## Strip binary
endif()

add_executable(covert main.c)
target_link_libraries(covert psapi shlwapi bcrypt)