add_executable(access access.c)
set_target_properties(access PROPERTIES COMPILE_FLAGS "-O3 -Wall -Wunused -Wpedantic")
