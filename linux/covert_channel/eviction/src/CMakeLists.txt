add_executable(covert_channel main.c)
set_target_properties(ev_chk PROPERTIES LINK_FLAGS "-static")
target_link_libraries(ev_chk cmdline_lib dynarray_lib list_lib filemap_lib pageflags_lib pthread)
