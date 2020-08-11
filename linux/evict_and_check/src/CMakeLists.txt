add_executable(ev_chk main.c)

if(NOT(CMAKE_BUILD_TYPE STREQUAL "debug"))
	#set_target_properties(ev_chk PROPERTIES LINK_FLAGS "-static")
endif()

target_link_libraries(ev_chk cmdline_lib dynarray_lib list_lib filemap_lib pageflags_lib pthread)
