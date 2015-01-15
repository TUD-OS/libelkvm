#pragma once

#define GDBSTUB_EXECUTION_BREAKPOINT    (0xac1)
#define GDBSTUB_TRACE                   (0xac2)
#define GDBSTUB_USER_BREAK              (0xac3)

typedef unsigned char  Bit8u;
typedef unsigned short Bit16u;
typedef unsigned short bx_bool;
typedef unsigned long  Bit32u;
typedef uint64_t Bit64u;

#define FMT_ADDRX64 "%016lx"
#define GDBSTUB_STOP_NO_REASON -1

static void write_signal(char* buf, int signal);
static void put_reply(const char* buffer);
void hex2mem(char* buf, unsigned char* mem, int count);
char* mem2hex(const Bit8u* mem, char* buf, int count);
