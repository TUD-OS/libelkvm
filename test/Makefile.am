AM_CPPFLAGS = -I$(top_srcdir)/include
TESTS = test_libelkvm
bin_PROGRAMS = test_libelkvm
test_libelkvm_SOURCES = test_kvm.c \
	test_pager.c \
	test_vcpu.c \
	test_vm.c \
	runner.c
test_libelkvm_LDADD = ../src/libelkvm.la
