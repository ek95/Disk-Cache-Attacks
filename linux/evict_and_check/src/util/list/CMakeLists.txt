add_library(list_lib list.c list.h)
set_target_properties(list_lib PROPERTIES COMPILE_FLAGS "-O3 -Wall -Wunused -Wpedantic")
