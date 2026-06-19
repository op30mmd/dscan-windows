cmake_minimum_required(VERSION 3.20)
project(dscan LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
  add_compile_options(/W4 /permissive- /O2 /EHsc /utf-8)
  add_compile_definitions(UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
else()
  add_compile_options(-Wall -Wextra -O2 -msse4.2)
  add_compile_definitions(UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -municode")
endif()

add_library(xxhash STATIC dscan/third_party/xxhash/xxhash.c)
target_include_directories(xxhash PUBLIC dscan/third_party/xxhash)

add_library(miniz STATIC dscan/third_party/miniz/miniz.c)
target_include_directories(miniz PUBLIC dscan/third_party/miniz)

file(GLOB_RECURSE DSCAN_SRC CONFIGURE_DEPENDS dscan/src/*.cpp)
add_executable(dscan ${DSCAN_SRC})
target_include_directories(dscan PRIVATE dscan/include)
target_link_libraries(dscan PRIVATE xxhash miniz shell32)
