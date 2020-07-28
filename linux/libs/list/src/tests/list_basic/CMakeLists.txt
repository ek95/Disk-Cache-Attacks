add_executable(test_list_basic test_list_basic.c)
set_target_properties(test_list_basic PROPERTIES COMPILE_FLAGS "-g -fsanitize=address" LINK_FLAGS "-fsanitize=address")
target_link_libraries(test_list_basic list_lib)

add_test(NAME list_basic COMMAND test_list_basic)
