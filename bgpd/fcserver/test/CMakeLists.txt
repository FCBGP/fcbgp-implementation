cmake_minimum_required(VERSION 3.5)

project(fcserver)

set(CMAKE_C_STANDARD 11)

add_compile_options(-Wall -g)

add_executable(test test.c)
target_link_libraries(test crypto ssl)

