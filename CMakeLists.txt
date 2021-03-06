PROJECT( libelkvm )
cmake_minimum_required(VERSION 2.8)
option(libelkvm_build_tests "Build all of libelkvm's unit tests." OFF)
option(libelkvm_generate_coverage "Generate coverage information for libelkvm's unit tests" OFF)

find_package(Boost 1.54.0 REQUIRED
             COMPONENTS log)

include_directories ("${PROJECT_SOURCE_DIR}/include/elkvm" "${PROJECT_SOURCE_DIR}/src" )

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11 -DBOOST_LOG_DYN_LINK")
add_definitions(-Wall -Wextra -Weffc++)
add_definitions(-D_PREFIX_="${CMAKE_INSTALL_PREFIX}")
list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/Modules)

if(libelkvm_build_tests)
    enable_testing()
    include(gmock)
endif()

if(libelkvm_generate_coverage)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-arcs -ftest-coverage")
    set(CMAKE_EXE_LINKER_FLAGS="${CMAKE_EXE_LINKER_FLAGS} -fprofile-arcs -ftest-coverage -lgcov")
    include(lcov)
endif()

SET( CMAKE_BUILD_TYPE Debug )
find_package(libelf REQUIRED)
find_package(libudis86)
if(LIBUDIS86_FOUND)
  set(HAVE_LIBUDIS86 ON)
  include_directories("${LIBUDIS86_INCLUDE_DIRS}")
endif(LIBUDIS86_FOUND)

configure_file(${CMAKE_SOURCE_DIR}/include/elkvm/config.h.cmake
               ${CMAKE_SOURCE_DIR}/include/elkvm/config.h)

add_subdirectory( share )
add_subdirectory( include )
add_subdirectory( src )
add_subdirectory( examples )

if (libelkvm_build_tests)
    add_subdirectory( test )
endif()
