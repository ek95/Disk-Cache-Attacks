add_library(cmdline_lib cmdline.c cmdline.h)
set_target_properties(cmdline_lib PROPERTIES COMPILE_FLAGS "-O3 -Wall -Wunused -Wpedantic")