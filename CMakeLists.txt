cmake_minimum_required(VERSION 3.10)
project(FileUnnest VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_options(-Wall -Wextra -O2)

find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include ${ZLIB_INCLUDE_DIRS})

set(LIB_SOURCES
    src/ftype.cpp
    src/utils.cpp
    src/engine.cpp
    src/extractors/archive_extractor.cpp
    src/extractors/ole2_extractor.cpp
    src/extractors/rtf_extractor.cpp
    src/extractors/onenote_extractor.cpp
    src/extractors/pdf_extractor.cpp
    src/extractors/asar_extractor.cpp
    src/extractors/svg_extractor.cpp
    src/extractors/psd_extractor.cpp
    src/extractors/indd_extractor.cpp
    src/extractors/pyinstaller_extractor.cpp
    src/extractors/carve_extractor.cpp
    src/extractors/disk_extractor.cpp
)

add_library(fileunnest_core STATIC ${LIB_SOURCES})
target_link_libraries(fileunnest_core PUBLIC ${ZLIB_LIBRARIES} ${CMAKE_DL_LIBS} Threads::Threads)

add_executable(fileunnest src/main.cpp)
target_link_libraries(fileunnest PRIVATE fileunnest_core)

add_executable(demo_unnest examples/demo_unnest.cpp)
target_link_libraries(demo_unnest PRIVATE fileunnest_core)

enable_testing()
add_executable(test_unnest tests/test_unnest.cpp)
target_link_libraries(test_unnest PRIVATE fileunnest_core)
add_test(NAME TestUnnest COMMAND test_unnest)
