cmake_minimum_required(VERSION 3.7)

project(DynamoRIO_dmti)

set(output_dir "${PROJECT_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${output_dir}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${output_dir}")
set(SHOW_RESULTS_DEFAULT ON)
set(OPT_CFLAGS "-O3")

set(ARM_V85_FLAG "-march=armv8.5-a+memtag")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -ggdb3 ${ARM_V85_FLAG}")
set(CMAKE_VERBOSE_MAKEFILE ON)

find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OPT_CFLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OPT_CFLAGS}")

file(GLOB SOURCES "src/*.c")
add_library(dmti SHARED ${SOURCES})
configure_DynamoRIO_client(dmti)

# Use Extensions
use_DynamoRIO_extension(dmti drwrap)


include_directories(/usr/lib/aarch64-linux-gnu/include)

find_library(CJSON_LIBRARY cjson HINTS /usr/aarch64-linux-gnu/lib)
find_library(LLVM_LIBC_INCLUDE_SCUDO scudo HINTS /usr/aarch64-linux-gnu/lib)

target_link_libraries(dmti cjson)
