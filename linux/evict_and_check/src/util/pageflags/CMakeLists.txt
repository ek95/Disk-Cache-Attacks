add_library(pageflags_lib pageflags.c pageflags.h)
set_target_properties(pageflags_lib PROPERTIES COMPILE_FLAGS "-O3 -Wall -Wunused -Wpedantic")
