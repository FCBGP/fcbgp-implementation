cmake_minimum_required(VERSION 3.10)

project(FCServer VERSION 0.4.0 LANGUAGES C)

configure_file("${PROJECT_SOURCE_DIR}/config/config.h.in"
    "${PROJECT_BINARY_DIR}/config/config.h")

# configurations
add_library(main_compiler_options INTERFACE)
set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Debug or Release")
message(STATUS "CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
if(CMAKE_BUILD_TYPE STREQUAL Debug)
    target_compile_options(main_compiler_options INTERFACE -O0 -g -ggdb
        -Wall -Wno-deprecated-declarations
        )
elseif(CMAKE_BUILD_TYPE STREQUAL Release)
    target_compile_options(main_compiler_options INTERFACE -O3
        -Wall -Wno-deprecated-declarations
        )
endif()

# pkg-config
find_package(PkgConfig REQUIRED)
if(PkgConfig_FOUND)
    message(STATUS "Found PkgConfig: ${PKG_CONFIG_VERSION_STRING}")
else()
    message(FATAL_ERROR "PkgConfig is not found!")
endif()

# libs
## We need Python3.6+ for f-string
find_package(Python3 REQUIRED COMPONENTS Interpreter Development)
if(NOT Python3_FOUND OR Python3_VERSION VERSION_LESS "3.6")
    message(FATAL_ERROR "Python 3.6 or higher is required. Found version: ${Python3_VERSION}")
else()
    message(STATUS "Found Python3 ${Python3_EXECUTABLE}, version: ${Python3_VERSION}")
endif()

## sqlite
find_package(SQLite3 REQUIRED)
if(SQLite3_FOUND)
    message(STATUS "Found SQLite3, version: ${SQLite3_VERSION}")
else()
    message(FATAL_ERROR "SQLite3 is not found")
endif()

## OpenSSL
find_package(OpenSSL REQUIRED)
# pkg_check_modules(OPENSSL REQUIRED openssl)
if(OPENSSL_FOUND)
    message(STATUS "Found OPENSSL, version: ${OPENSSL_VERSION}")
    string(REGEX MATCH "[0-9]+" OPENSSL_VERSION_MAJOR "${OPENSSL_VERSION}" CACHE)
    string(REGEX MATCH "[0-9]+" OPENSSL_VERSION_MINOR "${OPENSSL_VERSION}" CACHE)

    if(OPENSSL_VERSION_MAJOR EQUAL 3)
        message(STATUS "OPENSSL: ${OPENSSL_INCLUDE_DIR} | ${OPENSSL_LIBRARIES}")
    else()
        message(FATAL_ERROR "OpenSSL version is not 3.x, found version: ${OPENSSL_VERSION}")
    endif()
else()
    message(FATAL_ERROR "OPENSSL not found!")
endif()

# target
add_executable(fcserver
    # server
    src/fcserver.c
    src/fcfront.c
    src/fcconfig.c
    # messages
    src/messages/keyinfo.c
    src/messages/bm.c
    src/messages/topo.c
    src/messages/acl.c
    # utils
    src/utils/dbutils.c
    src/utils/sigutils.c
    src/utils/hashutils.c
    src/utils/pyutils.c
    src/utils/strutils.c
    # libs
    libs/linenoise/linenoise.c
    libs/diaglib/libdiag.c
    libs/cJSONlib/cJSON.c
    libs/htablelib/libhtable.c
    libs/baselib/libstring.c
    libs/baselib/liblist.c
    libs/baselib/libcrc32.c
    )

target_include_directories(fcserver PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/linenoise
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/baselib
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/diaglib
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/cJSONlib
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/htablelib
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/md5lib
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/
    ${PROJECT_BINARY_DIR}/config/
    ${SQLite3_INCLUDE_DIRS}
    ${Python3_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    )

target_link_libraries(fcserver PRIVATE
    m pthread
    ${SQLite3_LIBRARIES}
    ${Python3_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    main_compiler_options
    )
