#Prelude
AC_INIT([libelkvm], [0.1], [florian.pester@tu-dresden.de])
AM_INIT_AUTOMAKE([foreign -Wall -Werror dist-bzip2])

#Check for programs
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_LIBTOOL

#Check for libraries
AC_CHECK_LIB([cunit], [CU_add_suite])

#Check for header files
AC_CHECK_HEADERS([stdint.h])

#Check for typedefs, structs and compiler characteristics
AC_TYPE_UINT64_T

#Check for lib funcs

#Output files
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile test/Makefile])
AC_OUTPUT
