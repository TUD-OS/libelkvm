add_custom_target(coverage)
add_custom_command(TARGET coverage
  COMMAND mkdir -p cov
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_custom_command(TARGET coverage
  COMMAND lcov --directory . --zerocounters
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_custom_command(TARGET coverage
  COMMAND make test
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_custom_command(TARGET coverage
  COMMAND lcov --directory . --capture --output-file ./cov/coverage.info
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_custom_command(TARGET coverage
  COMMAND genhtml -o ./cov ./cov/coverage.info
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_dependencies(coverage elkvm)
