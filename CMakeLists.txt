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
endif()

add_library(xxhash STATIC dscan/third_party/xxhash/xxhash.c)
target_include_directories(xxhash PUBLIC dscan/third_party/xxhash)

add_library(miniz STATIC dscan/third_party/miniz/miniz.c)
target_include_directories(miniz PUBLIC dscan/third_party/miniz)

file(GLOB_RECURSE DSCAN_SRC CONFIGURE_DEPENDS dscan/src/*.cpp)
if(WIN32)
  list(APPEND DSCAN_SRC dscan/src/dscan.rc)
endif()
add_executable(dscan ${DSCAN_SRC})
target_include_directories(dscan PRIVATE dscan/include)
if(MSVC OR MINGW)
  target_link_libraries(dscan PRIVATE xxhash miniz shell32 ole32 oleaut32 uuid)
else()
  target_link_libraries(dscan PRIVATE xxhash miniz)
endif()

enable_testing()

add_executable(test_crc32c dscan/tests/test_crc32c.cpp dscan/src/Crc32c.cpp)
target_include_directories(test_crc32c PRIVATE dscan/include)

add_executable(test_path_normalization dscan/tests/test_path_normalization.cpp)
target_include_directories(test_path_normalization PRIVATE dscan/include)

add_executable(test_verdicts dscan/tests/test_verdicts.cpp
    dscan/src/detectors/JpegDetector.cpp
    dscan/src/detectors/PngDetector.cpp
    dscan/src/detectors/ZipDetector.cpp
    dscan/src/FileReader.cpp
    dscan/src/Crc32c.cpp
    dscan/src/Config.cpp
)
target_include_directories(test_verdicts PRIVATE dscan/include dscan/third_party/miniz dscan/third_party/xxhash)
target_link_libraries(test_verdicts PRIVATE miniz xxhash)

add_executable(test_detectors dscan/tests/test_detectors.cpp)
target_include_directories(test_detectors PRIVATE dscan/include dscan/third_party/xxhash)

add_test(NAME test_crc32c COMMAND test_crc32c)
add_test(NAME test_path_normalization COMMAND test_path_normalization)
add_test(NAME test_verdicts COMMAND test_verdicts)
add_test(NAME test_detectors COMMAND test_detectors)
