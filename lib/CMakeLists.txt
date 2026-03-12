cmake_minimum_required(VERSION 3.16)
project(openskills-crypto C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Glob all .c files from lib/src/*/
file(GLOB_RECURSE SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/*/*.c")

# Compile as a static library
add_library(openskills-crypto STATIC ${SOURCES})

# Include directories
target_include_directories(openskills-crypto PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Common warning flags
target_compile_options(openskills-crypto PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Werror=implicit-function-declaration
    -Werror=return-type
    -Wno-unused-parameter
)
