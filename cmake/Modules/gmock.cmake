include(ExternalProject)

ExternalProject_Add(project_gmock
  URL https://googlemock.googlecode.com/files/gmock-1.7.0.zip
  PREFIX ${CMAKE_CURRENT_BINARY_DIR}/gmock-1.7.0
  INSTALL_COMMAND ""
)
ExternalProject_Get_Property(project_gmock source_dir)
ExternalProject_Get_Property(project_gmock binary_dir)
set(GMOCK_DIR ${source_dir})
set(GMOCK_INSTALL_DIR ${binary_dir})

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    # force this option to ON so that Google Test will use /MD instead of /MT
    # /MD is now the default for Visual Studio, so it should be our default, too
    option(gtest_force_shared_crt
           "Use shared (DLL) run-time lib even when Google Test is built as static lib."
           ON)
endif()

add_library(gmock STATIC IMPORTED)
add_library(gmock_main STATIC IMPORTED)
add_library(gtest STATIC IMPORTED)
add_library(gtest_main STATIC IMPORTED)

set_property(TARGET gmock
  PROPERTY IMPORTED_LOCATION ${GMOCK_INSTALL_DIR}/libgmock.a)
set_property(TARGET gmock_main
  PROPERTY IMPORTED_LOCATION ${GMOCK_INSTALL_DIR}/libgmock_main.a)
set_property(TARGET gtest
  PROPERTY IMPORTED_LOCATION ${GMOCK_INSTALL_DIR}/gtest/libgtest.a)
set_property(TARGET gtest_main
  PROPERTY IMPORTED_LOCATION ${GMOCK_INSTALL_DIR}/gtest/libgtest_main.a)

add_dependencies(gmock project_gmock)
add_dependencies(gmock_main project_gmock)
add_dependencies(gtest project_gtest)
add_dependencies(gtest_main project_gtest)

set_property(TARGET gtest APPEND_STRING PROPERTY COMPILE_FLAGS " -w")

include_directories(SYSTEM ${GMOCK_DIR}/gtest/include
                           ${GMOCK_DIR}/include)

#
# add_gmock_test(<target> <sources>...)
#
#  Adds a Google Mock based test executable, <target>, built from <sources> and
#  adds the test so that CTest will run it. Both the executable and the test
#  will be named <target>.
#
function(add_gmock_test target)
    include_directories("${PROJECT_SOURCE_DIR}/include")
    add_executable(${target} ${ARGN})
    target_link_libraries(${target} gmock gmock_main)
    target_link_libraries(${target} gtest gtest_main)
    target_link_libraries(${target} boost_log)
    target_link_libraries(${target} pthread)
    target_link_libraries(${target} elkvm)
    add_test(${target} ${target})

    add_custom_command(TARGET ${target}
                       POST_BUILD
                       COMMAND ${target}
                       WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                       COMMENT "Running ${target}" VERBATIM)

endfunction()




