add_library(tsc_bench_lib tsc_bench.c tsc_bench.h)

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  add_subdirectory(tests)
endif()