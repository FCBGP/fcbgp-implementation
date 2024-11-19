cmake_minimum_required(VERSION 3.5)
project(ifinfo)

set(CMAKE_C_STANDARD 11)
add_compile_options(-g)

add_executable(test test.c ifinfo.c)
