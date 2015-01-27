OBJ = syscalls.o

CFLAGS += -std=c99

all : sysbench syscall_test

sysbench : $(OBJ)
	$(CC) -o sysbench $(OBJ) -static

syscall_test : $(OBJ:.o=.c)
	$(CC) -DFAST_BENCH -std=c99 syscalls.c -o syscall_test -static

	
clean :
	$(RM) $(OBJ) sysbench syscall_test
