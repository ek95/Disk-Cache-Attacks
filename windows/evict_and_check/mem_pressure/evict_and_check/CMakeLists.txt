cmake_minimum_required(VERSION 3.9)
project(ev_chk C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_BUILD_TYPE Debug)
if(CMAKE_COMPILER_IS_GNUCXX)
   set(CMAKE_EXE_LINKER_FLAGS "-s")  ## Strip binary
endif()

add_executable(ev_chk main.c)
set_target_properties(ev_chk PROPERTIES COMPILE_FLAGS "-m64" LINK_FLAGS "-m64")
target_link_libraries(ev_chk psapi shlwapi bcrypt)
