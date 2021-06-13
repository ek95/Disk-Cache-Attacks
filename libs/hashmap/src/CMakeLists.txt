add_library(hashmap_lib hashmap.c hashmap.h)
target_link_libraries(hashmap_lib list_lib)

add_subdirectory(tests)
