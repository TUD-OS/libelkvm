AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src/list -D'_PREFIX_="$(prefix)"'
lib_LTLIBRARIES = libelkvm.la
libelkvm_la_SOURCES = debug.c \
											elfloader.c \
											gdt.c\
											heap.c\
											idt.c\
											mapping.c\
										 	pager.c \
											stack.c \
											syscall.c\
											region.c\
											tss.c\
											vcpu.c \
											list/list.c\
										 	vm.c
libelkvmdir = $(datadir)/libelkvm
libelkvm_DATA = ../share/entry\
								../share/isr
