add_executable(covert_channel main.c)

if(NOT(CMAKE_BUILD_TYPE STREQUAL "debug"))
	set_target_properties(covert_channel PROPERTIES LINK_FLAGS "-static")
endif()

target_link_libraries(covert_channel tsc_bench_lib cmdline_lib fca_lib filemap_lib hashmap_lib)
