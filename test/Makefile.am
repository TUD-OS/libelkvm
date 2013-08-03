AM_CPPFLAGS = -I$(top_srcdir)/include
TESTS = test_libelkvm
check_PROGRAMS = test_libelkvm
test_libelkvm_SOURCES = test_elfloader.c \
												test_gdt.c\
											  test_kvm.c \
	                      test_pager.c \
												test_stack.c \
	                      test_vcpu.c \
	                      test_vm.c \
	                      runner.c
test_libelkvm_CFLAGS = @CHECK_CFLAGS@
test_libelkvm_LDADD = $(top_builddir)/src/libelkvm.la @CHECK_LIBS@

