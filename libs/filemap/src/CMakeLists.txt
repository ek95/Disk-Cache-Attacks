add_library(filemap_lib filemap.c filemap.h)
target_link_libraries(filemap_lib tsc_bench_lib)
