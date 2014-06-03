# Locate libelf library
# This module defines
# LIBELF_FOUND - System has libelf
# LIBELF_INCLUDE_DIRS - The libelf include directories
# LIBELF_LIBRARIES - The libraries needed to use libelf

# Note that the expected include convention is
# #include <libelf.h>
# and not
# #include <libelf/libelf.h>
# This is because the libelf includes may live in a location other than
# libelf/
#
# based on:
#   https://github.com/rlsosborne/tool_axe/blob/master/cmake/Modules/FindLibElf.cmake

find_path(LIBELF_INCLUDE_DIR libelf.h PATH_SUFFIXES libelf)
if("${LIBELF_INCLUDE_DIR}" MATCHES "libelf$")
  # If the libelf headers live in a libelf subdirectory then they might
  # include each other using the libelf/ prefix. Add the parent
  # directory to the list of include directories to make this work.
  string(REGEX REPLACE "libelf$" "" LIBELF_INCLUDE_DIRS
         "${LIBELF_INCLUDE_DIR}")
  set(LIBELF_INCLUDE_DIRS
      "${LIBELF_INCLUDE_DIRS}"
      "${LIBELF_INCLUDE_DIR}")
else()
  set(LIBELF_INCLUDE_DIRS "${LIBELF_INCLUDE_DIR}")
endif()
find_library(LIBELF_LIBRARIES elf)

include(FindPackageHandleStandardArgs)
# Sets LIBELF_FOUND
find_package_handle_standard_args(LibElf DEFAULT_MSG LIBELF_LIBRARIES LIBELF_INCLUDE_DIRS)

mark_as_advanced(LIBELF_INCLUDE_DIRS LIBELF_LIBRARIES)
