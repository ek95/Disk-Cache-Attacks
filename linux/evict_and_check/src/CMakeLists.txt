add_subdirectory(util)

add_executable(ev_chk main.c)
set_target_properties(ev_chk PROPERTIES COMPILE_FLAGS "-O3 -Wall -Wunused -Wpedantic" LINK_FLAGS "-static")
target_link_libraries(ev_chk cmdline_lib dynarray_lib list_lib pageflags_lib pthread)
