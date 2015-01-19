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

namespace Elkvm {
namespace Debug {

  void hex2mem(char* buf, unsigned char* mem, int count);
  char* mem2hex(const Bit8u* mem, char* buf, int count);

  class gdb_session {
    private:
      const int port = 1234;
      int listen_socket_fd;
      int socket_fd;

      unsigned char read_cmd_into_buffer(char *buffer);
      bool validate_checksum(unsigned char checksum);
      void get_command(char* buffer);

      void handle_query(char buffer[255]);
      void handle_continue(char buffer[255], VM &vm);
      void handle_singlestep(VM &vm);
      void handle_memwrite(VM &vm, char buffer[255]);
      void handle_memread(VM &vm, char buffer[255]);
      void handle_regread(VM &vm);
      void handle_qm();

      void put_reply(const char* buffer);
      void put_sigtrap_reply();
      void put_debug_char(char ch);
      void flush_debug_buffer();
      char get_debug_char();
      void write_signal(char* buf, int signal);

      void debug_loop(Elkvm::VM &vm);
      void wait_for_connection();

    public:
      gdb_session(Elkvm::VM &vm);
  };

//namespace Debug
}
//namespace Elkvm
}
