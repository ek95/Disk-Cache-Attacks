add_library(dynarray_lib dynarray.c dynarray.h)
set_target_properties(dynarray_lib PROPERTIES COMPILE_FLAGS "-O3 -Wall -Wunused -Wpedantic")