#include <elkvm/elkvm.h>
#include <elkvm/elkvm-log.h>

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

long elkvm_do_sendfile(Elkvm::VM * vmi __attribute__((unused))) {
  ERROR() << "unimplemented"; exit(1);
  return -ENOSYS;
}

long elkvm_do_socket(Elkvm::VM * vmi __attribute__((unused))) {
  CURRENT_ABI::paramtype domain;
  CURRENT_ABI::paramtype type;
  CURRENT_ABI::paramtype protocol;

  vmi->unpack_syscall(&domain, &type, &protocol);
  return vmi->get_handlers()->socket(domain, type, protocol);
}

long elkvm_do_connect(Elkvm::VM * vmi __attribute__((unused))) {
  ERROR() << "unimplemented"; exit(1);
  return -ENOSYS;
}

long elkvm_do_accept(Elkvm::VM * vmi __attribute__((unused))) {
  CURRENT_ABI::paramtype sock;
  CURRENT_ABI::paramtype addr;
  CURRENT_ABI::paramtype len;
  struct sockaddr* local_addr = 0;
  socklen_t *local_len = 0;

  vmi->unpack_syscall(&sock, &addr, &len);

  if (addr != 0) {
	local_addr = reinterpret_cast<struct sockaddr*>(vmi->get_region_manager()->get_pager().get_host_p(addr));
  }
  if (len != 0) {
	local_len =  reinterpret_cast<socklen_t*>(vmi->get_region_manager()->get_pager().get_host_p(len));
  }

  return vmi->get_handlers()->accept(sock, local_addr, local_len);
}

long elkvm_do_sendto(Elkvm::VM * vmi __attribute__((unused))) {
  ERROR() << "unimplemented"; exit(1);
  return -ENOSYS;
}

long elkvm_do_recvfrom(Elkvm::VM * vmi __attribute__((unused))) {
  ERROR() << "unimplemented"; exit(1);
  return -ENOSYS;
}

long elkvm_do_sendmsg(Elkvm::VM * vmi __attribute__((unused))) {
  ERROR() << "unimplemented"; exit(1);
  return -ENOSYS;
}

long elkvm_do_recvmsg(Elkvm::VM * vmi __attribute__((unused))) {
  ERROR() << "unimplemented"; exit(1);
  return -ENOSYS;
}

long elkvm_do_shutdown(Elkvm::VM * vmi __attribute__((unused))) {
  ERROR() << "unimplemented"; exit(1);
  return -ENOSYS;
}

long elkvm_do_bind(Elkvm::VM * vmi __attribute__((unused))) {
  CURRENT_ABI::paramtype sock;
  CURRENT_ABI::paramtype addr;
  CURRENT_ABI::paramtype addrlen;

  vmi->unpack_syscall(&sock, &addr, &addrlen);
  const struct sockaddr* local_addr = 0;
  if (addr) {
	local_addr = reinterpret_cast<const struct sockaddr*>(vmi->get_region_manager()->get_pager().get_host_p(addr));
  }

  return vmi->get_handlers()->bind(sock, local_addr, addrlen);
}

long elkvm_do_listen(Elkvm::VM * vmi __attribute__((unused))) {
  CURRENT_ABI::paramtype sock;
  CURRENT_ABI::paramtype backlog;

  vmi->unpack_syscall(&sock, &backlog);
  return vmi->get_handlers()->listen(sock, backlog);
}

long elkvm_do_getsockname(Elkvm::VM * vmi __attribute__((unused))) {
  CURRENT_ABI::paramtype sock;
  CURRENT_ABI::paramtype addr;
  CURRENT_ABI::paramtype len;
  struct sockaddr* local_addr = 0;
  socklen_t *local_len = 0;

  vmi->unpack_syscall(&sock, &addr, &len);

  if (addr != 0) {
	local_addr = reinterpret_cast<struct sockaddr*>(vmi->get_region_manager()->get_pager().get_host_p(addr));
  }
  if (len != 0) {
	local_len =  reinterpret_cast<socklen_t*>(vmi->get_region_manager()->get_pager().get_host_p(len));
  }
  return vmi->get_handlers()->getsockname(sock, local_addr, local_len);
}

long elkvm_do_getpeername(Elkvm::VM * vmi __attribute__((unused))) {
  ERROR() << "unimplemented"; exit(1);
  return -ENOSYS;
}

long elkvm_do_socketpair(Elkvm::VM * vmi __attribute__((unused))) {
  ERROR() << "unimplemented"; exit(1);
  return -ENOSYS;
}

long elkvm_do_setsockopt(Elkvm::VM * vmi __attribute__((unused))) {
  CURRENT_ABI::paramtype sock;
  CURRENT_ABI::paramtype lvl;
  CURRENT_ABI::paramtype optname;
  CURRENT_ABI::paramtype optval;
  CURRENT_ABI::paramtype optlen;

  void* local_optval = 0;

  vmi->unpack_syscall(&sock, &lvl, &optname, &optval, &optlen);

  if (optval != 0) {
	local_optval = vmi->get_region_manager()->get_pager().get_host_p(optval);
  }

  return vmi->get_handlers()->setsockopt(sock, lvl, optname, local_optval, optlen);
}

long elkvm_do_getsockopt(Elkvm::VM * vmi __attribute__((unused))) {
  ERROR() << "unimplemented"; exit(1);
  return -ENOSYS;
}

