.PHONY: clean

CC=gcc
CFLAGS=-Wall -Wextra -std=gnu99 -I ./include
DEBUGFLAGS=-O0 -D_DEBUG -g

TARGET=libkvmos.so

REQUIRES_LIBS=
LDFLAGS=-shared -l$(REQUIRES_LIBS)


OBJ=

all: $(OBJ)
	$(CC) $(CFLAGS) $(DEBUGFLAGS) -o $(TARGET) $(OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o $(BINARY)

