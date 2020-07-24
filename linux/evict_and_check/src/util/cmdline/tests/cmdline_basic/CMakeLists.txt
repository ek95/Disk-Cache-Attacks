add_executable(test_cmdline_basic test_cmdline_basic.c)
set_target_properties(test_cmdline_basic PROPERTIES COMPILE_FLAGS "-g -fsanitize=address" LINK_FLAGS "-fsanitize=address")
target_link_libraries(test_cmdline_basic cmdline_lib)

add_test(NAME cmdline_basic COMMAND test_cmdline_basic)
