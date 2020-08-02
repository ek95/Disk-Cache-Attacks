add_executable(covert_channel main.c)
set_target_properties(covert_channel PROPERTIES COMPILE_FLAGS "-O3 -Wall -Wunused -Wpedantic" LINK_FLAGS "-static")
target_link_libraries(covert_channel pthread rt)
