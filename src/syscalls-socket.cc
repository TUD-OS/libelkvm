#include <elkvm/elkvm.h>
#include <elkvm/elkvm-log.h>

#include <errno.h>

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
  ERROR() << "unimplemented"; exit(1);
  return -ENOSYS;
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
  ERROR() << "unimplemented"; exit(1);
  return -ENOSYS;
}

long elkvm_do_listen(Elkvm::VM * vmi __attribute__((unused))) {
  ERROR() << "unimplemented"; exit(1);
  return -ENOSYS;
}

long elkvm_do_getsockname(Elkvm::VM * vmi __attribute__((unused))) {
  ERROR() << "unimplemented"; exit(1);
  return -ENOSYS;
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
  ERROR() << "unimplemented"; exit(1);
  return -ENOSYS;
}

long elkvm_do_getsockopt(Elkvm::VM * vmi __attribute__((unused))) {
  ERROR() << "unimplemented"; exit(1);
  return -ENOSYS;
}

