add_executable(test_hashmap_basic test_hashmap_basic.c)
set_target_properties(test_hashmap_basic PROPERTIES COMPILE_FLAGS "-g -fsanitize=address" LINK_FLAGS "-fsanitize=address")
target_link_libraries(test_hashmap_basic hashmap_lib)

add_test(NAME hashmap_basic COMMAND test_hashmap_basic)
