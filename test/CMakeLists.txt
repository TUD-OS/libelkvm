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

