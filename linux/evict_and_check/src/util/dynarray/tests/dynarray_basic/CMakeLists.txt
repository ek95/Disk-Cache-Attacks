add_executable(test_dynarray_basic test_dynarray_basic.c)
set_target_properties(test_dynarray_basic PROPERTIES COMPILE_FLAGS "-fsanitize=address" LINK_FLAGS "-fsanitize=address")
target_link_libraries(test_dynarray_basic dynarray_lib)

add_test(NAME dynarray_basic COMMAND test_dynarray_basic)
