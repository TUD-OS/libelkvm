/////////////////////////////////////////////////////////////////////////
// $Id: gdbstub.cc 11519 2012-10-28 08:23:39Z vruppert $
/////////////////////////////////////////////////////////////////////////
//
//  Copyright (C) 2002-2012  The Bochs Project Team
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 2 of the License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
//
/////////////////////////////////////////////////////////////////////////

#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <netdb.h>

#include <elkvm/elkvm.h>
#include <elkvm/elkvm-internal.h>
#include <elkvm/elkvm-log.h>
#include <elkvm/debug.h>
#include <elkvm/gdbstub.h>
#include <elkvm/pager.h>
#include <elkvm/regs.h>
#include <elkvm/region_manager.h>
#include <elkvm/vcpu.h>

//static bx_list_c *gdbstub_list;
static int listen_socket_fd;
static int socket_fd;
//static logfunctions *gdbstublog;

namespace Elkvm {
namespace Debug {

guestptr_t saved_eip = 0;

void handle_continue(char buffer[255], VM &vm) {
  DBG() << buffer;
  char buf[255];
  guestptr_t new_rip;
  VCPU &vcpu = *vm.get_vcpu(0);

  if (buffer[1] != 0) {
    new_rip = (guestptr_t) atoi(buffer + 1);

    printf("continuing at 0x%lx\n", new_rip);

    //TODO this is only used here, get rid of it!
    saved_eip = vcpu.get_reg(Elkvm::Reg_t::rip);

    //BX_CPU_THIS_PTR gen_reg[BX_32BIT_REG_EIP].dword.erx = new_eip;
    //TODO reset the rip, set kvm_regs
    vcpu.set_reg(Elkvm::Reg_t::rip, new_rip);
  }

  vm.run();

  //if (buffer[1] != 0)
  //{
  //  BX_CPU_THIS_PTR gen_reg[BX_32BIT_REG_EIP].dword.erx = saved_eip;
  //}

  buf[0] = 'S';
  write_signal(&buf[1], SIGTRAP);
  put_reply(buf);
}

void handle_singlestep(VM &vm) {
  DBG();
  char buf[255];

  auto vcpu = *vm.get_vcpu(0);
  vcpu.singlestep();
  vm.run();
  vcpu.singlestep_off();

  buf[0] = 'S';
  write_signal(&buf[1], SIGTRAP);
  put_reply(buf);
}

void handle_memwrite(VM &vm, char buffer[255]) {
  DBG();
  unsigned char mem[255];
  char* ebuf;

  guestptr_t addr = strtoull(&buffer[1], &ebuf, 16);
  int len = strtoul(ebuf + 1, &ebuf, 16);
  hex2mem(ebuf + 1, mem, len);

  void *host_p = vm.get_region_manager()->get_pager().get_host_p(addr);
  memcpy(host_p, mem, len);
  auto vcpu = *vm.get_vcpu(0);

  int err = vcpu.enable_software_breakpoints();
  assert(err == 0 && "could not set guest debug mode");

  put_reply("OK");
}

void handle_memread(VM &vm, char buffer[255]) {
  DBG();

  char* ebuf;
  guestptr_t addr = strtoull(&buffer[1], &ebuf, 16);
  int len = strtoul(ebuf + 1, NULL, 16);

  DBG() << std::hex << "addr: " << addr << " len: " << len;

  if(addr == 0x0) {
    put_reply("");
  } else {
    void *host_p = vm.get_region_manager()->get_pager().get_host_p(addr);
    DBG() << "host_p: " << host_p;
    if(host_p != nullptr) {
      char obuf[1024];
      memcpy(obuf, host_p, len);

      mem2hex((Bit8u *)host_p, obuf, len);
      DBG() << obuf;
      put_reply(obuf);
    } else {
      put_reply("");
    }
  }
}

void handle_regread(VM &vm) {
  DBG();
#define PUTREG(buf, val, len) do { \
         Bit64u u = (val); \
         (buf) = mem2hex((const Bit8u*)&u, (buf), (len)); \
      } while (0)
  auto vcpu = *vm.get_vcpu(0);
  char obuf[1024];
  char* buf = obuf;
  PUTREG(buf, vcpu.get_reg(Elkvm::Reg_t::rax), 8);
  PUTREG(buf, vcpu.get_reg(Elkvm::Reg_t::rbx), 8);
  PUTREG(buf, vcpu.get_reg(Elkvm::Reg_t::rcx), 8);
  PUTREG(buf, vcpu.get_reg(Elkvm::Reg_t::rdx), 8);
  PUTREG(buf, vcpu.get_reg(Elkvm::Reg_t::rsi), 8);
  PUTREG(buf, vcpu.get_reg(Elkvm::Reg_t::rdi), 8);
  PUTREG(buf, vcpu.get_reg(Elkvm::Reg_t::rbp), 8);
  if(vcpu.get_reg(Elkvm::Reg_t::rip) < 0xffff800000000000) {
    PUTREG(buf, vcpu.get_reg(Elkvm::Reg_t::rsp), 8);
  } else {
    /* in kernel mode, figure out the real stack and return that
     * this really helps with backtraces (hopefully) */
    guestptr_t *sf = reinterpret_cast<guestptr_t *>(
        vm.get_region_manager()->get_pager().get_host_p(
          vcpu.get_reg(Elkvm::Reg_t::rsp) + 24)
        );
    guestptr_t real_rsp = *sf;
    PUTREG(buf, real_rsp, 8);
  }
  PUTREG(buf, vcpu.get_reg(Elkvm::Reg_t::r8),  8);
  PUTREG(buf, vcpu.get_reg(Elkvm::Reg_t::r9),  8);
  PUTREG(buf, vcpu.get_reg(Elkvm::Reg_t::r10), 8);
  PUTREG(buf, vcpu.get_reg(Elkvm::Reg_t::r11), 8);
  PUTREG(buf, vcpu.get_reg(Elkvm::Reg_t::r12), 8);
  PUTREG(buf, vcpu.get_reg(Elkvm::Reg_t::r13), 8);
  PUTREG(buf, vcpu.get_reg(Elkvm::Reg_t::r14), 8);
  PUTREG(buf, vcpu.get_reg(Elkvm::Reg_t::r15), 8);
  if(vcpu.get_reg(Elkvm::Reg_t::rip) < 0xffff800000000000) {
    PUTREG(buf, vcpu.get_reg(Elkvm::Reg_t::rip), 8);
  } else {
    /* in kernel mode, figure out the real stack and return that
     * this really helps with backtraces (hopefully) */
    guestptr_t *sf = reinterpret_cast<guestptr_t *>(
        vm.get_region_manager()->get_pager().get_host_p(
          vcpu.get_reg(Elkvm::Reg_t::rsp))
          );
    guestptr_t real_rip = *sf;
    PUTREG(buf, real_rip, 8);
  }
  PUTREG(buf, vcpu.get_reg(Elkvm::Reg_t::rflags), 8);
  PUTREG(buf, vcpu.get_reg(Elkvm::Seg_t::cs).get_base(), 8);
  PUTREG(buf, vcpu.get_reg(Elkvm::Seg_t::ss).get_base(), 8);
  PUTREG(buf, vcpu.get_reg(Elkvm::Seg_t::ds).get_base(), 8);
  PUTREG(buf, vcpu.get_reg(Elkvm::Seg_t::es).get_base(), 8);
  PUTREG(buf, vcpu.get_reg(Elkvm::Seg_t::fs).get_base(), 8);
  PUTREG(buf, vcpu.get_reg(Elkvm::Seg_t::gs).get_base(), 8);
  put_reply(obuf);
}

void handle_qm() {
  DBG();
  char obuf[1024];
  sprintf(obuf, "S%02x", SIGTRAP);
  put_reply(obuf);
}

void handle_query(char buffer[255]) {
  if (buffer[1] == 'C')
  {
    char obuf[1024];
    sprintf(obuf, FMT_ADDRX64, (Bit64u)1);
    put_reply(obuf);
  }
  else if (strncmp(&buffer[1], "Offsets", strlen("Offsets")) == 0)
  {
    char obuf[1024];
    sprintf(obuf, "Text=%x;Data=%x;Bss=%x", 0x0, 0x0, 0x0);
    put_reply(obuf);
  }
  else if (strncmp(&buffer[1], "Supported", strlen("Supported")) == 0)
  {
    put_reply("");
  }
  else
  {
    put_reply(""); /* not supported */
  }
}

//namespace Debug
}
//namespace Elkvm
}

static int hex(char ch)
{
  if ((ch >= 'a') && (ch <= 'f')) return(ch - 'a' + 10);
  if ((ch >= '0') && (ch <= '9')) return(ch - '0');
  if ((ch >= 'A') && (ch <= 'F')) return(ch - 'A' + 10);
  return(-1);
}

static char buf[4096], *bufptr = buf;

static void flush_debug_buffer()
{
  char *p = buf;
  while (p != bufptr) {
    int n = send(socket_fd, p, bufptr-p, 0);
    if (n == -1) {
      assert(false && "error on debug socket");
      break;
    }
    p += n;
  }
  bufptr = buf;
}

static void put_debug_char(char ch)
{
  if (bufptr == buf + sizeof buf)
    flush_debug_buffer();
  *bufptr++ = ch;
}

static char get_debug_char(void)
{
  char ch;

  recv(socket_fd, &ch, 1, 0);

  return(ch);
}

static const char hexchars[]="0123456789abcdef";

static void put_reply(const char* buffer)
{
  unsigned char csum;
  int i;

  DBG() << "put_reply: '" << buffer << "'\n";

  do {
    put_debug_char('$');

    csum = 0;

    i = 0;
    while (buffer[i] != 0)
    {
      put_debug_char(buffer[i]);
      csum = csum + buffer[i];
      i++;
    }

    put_debug_char('#');
    put_debug_char(hexchars[csum >> 4]);
    put_debug_char(hexchars[csum % 16]);
    flush_debug_buffer();
  } while (get_debug_char() != '+');
}

unsigned char read_cmd_into_buffer(char *buffer) {
  unsigned count = 0;
  unsigned char checksum = 0;
  char ch;
  while ((ch = get_debug_char()) != '#') {
    checksum = checksum + ch;
    buffer[count] = ch;
    count++;
  }
  buffer[count] = 0;
  std::cout << "cmd: " << buffer << std::endl;
  return checksum;
}

bool validate_checksum(unsigned char checksum) {
  unsigned char xmitcsum = hex(get_debug_char()) << 4;
  xmitcsum += hex(get_debug_char());
  return xmitcsum == checksum;
}

static void get_command(char* buffer) {
  bool checksum_correct = false;
  do {
    char ch;
    while ((ch = get_debug_char()) != '$');
    unsigned char checksum = read_cmd_into_buffer(buffer);

    checksum_correct = validate_checksum(checksum);
    if(checksum_correct) {
      put_debug_char('+');
      if (buffer[2] == ':') {
        put_debug_char(buffer[0]);
        put_debug_char(buffer[1]);
        unsigned count = strlen(buffer);
        for (unsigned i = 3; i <= count; i++) {
          buffer[i - 3] = buffer[i];
        }
      }
    } else {
      ERROR() << "Bad checksum!";
      put_debug_char('-');
    }
    flush_debug_buffer();
  } while (!checksum_correct);
}

void hex2mem(char* buf, unsigned char* mem, int count)
{
  unsigned char ch;

  for (int i = 0; i<count; i++)
  {
    ch = hex(*buf++) << 4;
    ch = ch + hex(*buf++);
    *mem++ = ch;
  }
}

char* mem2hex(const Bit8u* mem, char* buf, int count)
{
  for (int i = 0; i<count; i++)
  {
    Bit8u ch = *mem++;
    *buf++ = hexchars[ch >> 4];
    *buf++ = hexchars[ch % 16];
  }
  *buf = 0;
  return(buf);
}

int hexdigit(char c)
{
  if (isdigit(c))
    return c - '0';
  else if (isupper(c))
    return c - 'A' + 10;
  else
    return c - 'a' + 10;
}

Bit64u read_little_endian_hex(char *buf)
{
  int byte;
  Bit64u ret = 0;
  int n = 0;
  while (isxdigit(*buf)) {
    byte = hexdigit(*buf++);
    if (isxdigit(*buf))
      byte = (byte << 4) | hexdigit(*buf++);
    ret |= (Bit64u)byte << (n*8);
    ++n;
  }
  return ret;
}

static int continue_thread = -1;
static int other_thread = 0;

#if !BX_SUPPORT_X86_64
#define NUMREGS (16)
#define NUMREGSBYTES (NUMREGS * 4)
#endif

static void write_signal(char* buf, int signal)
{
  buf[0] = hexchars[signal >> 4];
  buf[1] = hexchars[signal % 16];
  buf[2] = 0;
}

static void debug_loop(const std::shared_ptr<Elkvm::VM>& vm) {
  char buffer[255];

  while (true)
  {
    get_command(buffer);
    DBG() << "get_buffer '" << buffer << "'\t";

    // At a minimum, a stub is required to support the ‘g’ and ‘G’
    // commands for register access,
    // and the ‘m’ and ‘M’ commands for memory access. Stubs that only
    // control single-threaded
    // targets can implement run control with the ‘c’ (continue), and
    // ‘s’ (step) commands. Stubs
    // that support multi-threading targets should support the ‘vCont’
    // command. All other commands
    // are optional.

    switch (buffer[0])
    {
      // 'c [addr]' Continue. addr is address to resume.
      // If addr is omitted, resume at current address.
      // This packet is deprecated for multi-threading support. See [vCont packet]
      case 'c':
      {
        Elkvm::Debug::handle_continue(buffer, *vm);
        break;
      }

      // 's [addr]' Single step. addr is the address at which to resume.
      // If addr is omitted, resume at same address.
      // This packet is deprecated for multi-threading support. See [vCont packet]
      case 's':
      {
        Elkvm::Debug::handle_singlestep(*vm);
        break;
      }

      // ‘M addr,length:XX...’
      // Write length bytes of memory starting at address addr. XX... is the data;
      // each byte is transmitted as a two-digit hexadecimal number.
      case 'M':
      {
        Elkvm::Debug::handle_memwrite(*vm, buffer);
        break;
      }

      // ‘m addr,length’
      // Read length bytes of memory starting at address addr. Note that addr may
      // not be aligned to any particular boundary.

      // The stub need not use any particular size or alignment when gathering data
      // from memory for the response; even if addr is word-aligned and length is a
      // multiple of the word size, the stub is free to use byte accesses, or not. For
      // this reason, this packet may not be suitable for accessing memory-mapped I/O
      // devices.
      case 'm':
      {
        Elkvm::Debug::handle_memread(*vm, buffer);
        break;
      }

      // ‘P n...=r...’
      // Write register n... with value r... The register number n is in hexadecimal,
      // and r... contains two hex digits for each byte in the register (target byte order).
//      case 'P':

      // ‘g’ Read general registers.
      case 'g':
      {
        Elkvm::Debug::handle_regread(*vm);
        break;
      }

      case '?': {
        Elkvm::Debug::handle_qm();
        break;
      }

      // ‘H op thread-id’
      // Set thread for subsequent operations (‘m’, ‘M’, ‘g’, ‘G’, et.al.). op depends on the
      // operation to be performed: it should be ‘c’ for step and continue operations
      // (note that this is deprecated, supporting the ‘vCont’ command is a better option),
      // ‘g’ for other operations. The thread designator thread-id has the format
      // and interpretation described in [thread-id syntax]
      case 'H':
                // XXX check if this is really needed!
        if (buffer[1] == 'c')
        {
          continue_thread = strtol(&buffer[2], NULL, 16);
          put_reply("OK");
        }
        else if (buffer[1] == 'g')
        {
          other_thread = strtol(&buffer[2], NULL, 16);
          put_reply("OK");
        }
        else
        {
          put_reply("Eff");
        }
        break;

      // ‘q name params...’
      // ‘Q name params...’
      // General query (‘q’) and set (‘Q’). These packets are described fully in
      // Section E.4 [General Query Packets]
      case 'q':
        Elkvm::Debug::handle_query(buffer);
        break;

      // ‘z type,addr,kind’
      // ‘Z type,addr,kind’
      // Insert (‘Z’) or remove (‘z’) a type breakpoint or watchpoint starting at address
      // address of kind kind.
      //case 'Z':
      //  do_breakpoint(vm, 1, buffer+1);
      //  break;
      //case 'z':
      //  do_breakpoint(vm, 0, buffer+1);
      //  break;

      // ‘k’ Kill request.
      case 'k':
        assert(false && "Debugger asked us to quit");
        break;

      case 'D':
        printf("Debugger detached");
        put_reply("OK");
        return;
        break;

      default:
        put_reply("");
        break;
    }
  }
}

static void wait_for_connect(int portn)
{
  struct sockaddr_in sockaddr;
  socklen_t sockaddr_len;
  struct protoent *protoent;
  int r;
  int opt;

  listen_socket_fd = socket(PF_INET, SOCK_STREAM, 0);
  if (listen_socket_fd == -1)
  {
    printf("Failed to create socket");
    exit(1);
  }

  /* Allow rapid reuse of this port */
  opt = 1;
  r = setsockopt(listen_socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  if (r == -1)
  {
    printf("setsockopt(SO_REUSEADDR) failed");
  }

  memset (&sockaddr, '\000', sizeof sockaddr);
#if BX_HAVE_SOCKADDR_IN_SIN_LEN
  // if you don't have sin_len change that to #if 0.  This is the subject of
  // bug [ 626840 ] no 'sin_len' in 'struct sockaddr_in'.
  sockaddr.sin_len = sizeof sockaddr;
#endif
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_port = htons(portn);
  sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);

  r = bind(listen_socket_fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
  if (r == -1)
  {
    assert(false && "Failed to bind socket");
  }

  r = listen(listen_socket_fd, 0);
  if (r == -1)
  {
    assert(false && "Failed to listen on socket");
  }

  sockaddr_len = sizeof sockaddr;
  socket_fd = accept(listen_socket_fd, (struct sockaddr *)&sockaddr, &sockaddr_len);
  if (socket_fd == -1)
  {
    assert(false && "Failed to accept on socket");
  }
  close(listen_socket_fd);

  protoent = getprotobyname ("tcp");
  if (!protoent)
  {
    printf("getprotobyname (\"tcp\") failed");
    return;
  }

  /* Disable Nagle - allow small packets to be sent without delay. */
  opt = 1;
  r = setsockopt (socket_fd, protoent->p_proto, TCP_NODELAY, &opt, sizeof(opt));
  if (r == -1)
  {
    printf("setsockopt(TCP_NODELAY) failed");
  }
  Bit32u ip = sockaddr.sin_addr.s_addr;
  printf("Connected to %ld.%ld.%ld.%ld\n", ip & 0xff, (ip >> 8) & 0xff, (ip >> 16) & 0xff, (ip >> 24) & 0xff);
}

void elkvm_gdbstub_init(const std::shared_ptr<Elkvm::VM>& vm) {
  int portn = 1234;

  /* Wait for connect */
  printf("Waiting for gdb connection on port %d\n", portn);
  wait_for_connect(portn);

  /* Do debugger command loop */
  debug_loop(vm);

  /* CPU loop */
  vm->run();
}
