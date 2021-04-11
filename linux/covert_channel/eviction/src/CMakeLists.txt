add_executable(covert_channel main.c)

if(NOT(CMAKE_BUILD_TYPE STREQUAL "debug"))
	set_target_properties(covert_channel PROPERTIES LINK_FLAGS "-static")
endif()

target_link_libraries(covert_channel cmdline_lib dynarray_lib list_lib filemap_lib pthread)
