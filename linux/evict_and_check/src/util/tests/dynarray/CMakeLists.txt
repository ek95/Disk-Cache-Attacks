add_executable(test_dynarray test_dynarray.c)
set_target_properties(test_dynarray PROPERTIES COMPILE_FLAGS "-O2 -g -Wall -Wunused -Wpedantic -fsanitize=address" LINK_FLAGS "-fsanitize=address")
target_link_libraries(test_dynarray dynarray_lib)
