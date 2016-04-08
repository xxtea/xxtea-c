project(xxtea)
cmake_minimum_required(VERSION 2.8.12)
set(CMAKE_MACOSX_RPATH 1)
set(LIBXXTEA_SRC xxtea.c)
add_library(xxtea SHARED ${LIBXXTEA_SRC})
add_library(xxtea_static STATIC ${LIBXXTEA_SRC})
set_target_properties(xxtea PROPERTIES VERSION 1.0 SOVERSION 1)
set_target_properties(xxtea_static PROPERTIES OUTPUT_NAME "xxtea")
set_target_properties(xxtea PROPERTIES CLEAN_DIRECT_OUTPUT 1)
set_target_properties(xxtea_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
set_target_properties(xxtea PROPERTIES INSTALL_RPATH "@loader_path/../lib")
set_target_properties(xxtea_static PROPERTIES INSTALL_RPATH "@loader_path/../lib")
install(TARGETS xxtea
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)
install(TARGETS xxtea_static
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)
install(FILES xxtea.h DESTINATION include)
