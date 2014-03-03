#Prelude
AC_INIT([libelkvm],[0.1],[florian.pester@tu-dresden.de])
AM_PROG_AR
AM_INIT_AUTOMAKE([foreign -Wall -Werror 1.9.6 subdir-objects])
AC_CONFIG_MACRO_DIR([m4])

#Check for programs
AC_PROG_CC
AC_PROG_CC_STDC
LT_INIT
AM_PROG_CC_C_O

#Check for libraries
AC_CHECK_LIB([elf], [elf_begin])
AC_CHECK_LIB([udis86], [ud_init])

#Check for header files
AC_CHECK_HEADERS([stdint.h])
AC_CHECK_HEADERS([libelf.h])
AC_CHECK_HEADERS([gelf.h])
AC_CHECK_HEADERS([signal.h])

#Check for typedefs, structs and compiler characteristics
AC_TYPE_UINT64_T

#Check for lib funcs
PKG_CHECK_MODULES([CHECK], [check >= 0.9.4])

#Output files
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile include/Makefile src/Makefile test/Makefile])
AC_OUTPUT
