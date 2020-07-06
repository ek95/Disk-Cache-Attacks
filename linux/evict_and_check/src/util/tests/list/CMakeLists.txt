add_executable(test_list test_list.c)
set_target_properties(test_list PROPERTIES COMPILE_FLAGS "-O2 -g -Wall -Wunused -Wpedantic -fsanitize=address" LINK_FLAGS "-fsanitize=address")
target_link_libraries(test_list list_lib)
