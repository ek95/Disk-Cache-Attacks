add_library(fca_lib fca.c fca.h osal.h)
target_link_libraries(fca_lib dynarray_lib list_lib hashmap_lib filemap_lib)
