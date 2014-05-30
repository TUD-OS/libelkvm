set(GMOCK_DIR "./include/gmock"
    CACHE PATH "The path to the GoogleMock test framework.")

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    # force this option to ON so that Google Test will use /MD instead of /MT
    # /MD is now the default for Visual Studio, so it should be our default, too
    option(gtest_force_shared_crt
           "Use shared (DLL) run-time lib even when Google Test is built as static lib."
           ON)
endif()

add_subdirectory(${GMOCK_DIR} ${CMAKE_BINARY_DIR}/gmock)

include_directories(SYSTEM ${GMOCK_DIR}/gtest/include
                           ${GMOCK_DIR}/include)


add_executable(libelkvm_test
    test_public_interface.cc
    )
target_link_libraries(libelkvm_test
    pthread)
target_link_libraries(libelkvm_test
    gmock
    gmock_main)
target_link_libraries(libelkvm_test
    gtest
    gtest_main)
add_test(elkvm-tests libelkvm_test)

