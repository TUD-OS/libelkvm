#include <sys/vfs.h>

#include <elkvm/elkvm.h>
#include <elkvm/syscall.h>

long elkvm_do_statfs(Elkvm::VM * vm) {
  if(vm->get_handlers()->statfs == nullptr) {
    INFO() <<"STATFS handler not found\n";
    return -ENOSYS;
  }

  guestptr_t path_p = 0x0;
  guestptr_t buf_p = 0x0;

  vm->unpack_syscall(&path_p, &buf_p);

  char *path = nullptr;
  struct statfs *buf = nullptr;
  if(path_p != 0x0) {
    path = static_cast<char *>(vm->host_p(path_p));
  }
  if(buf_p != 0x0) {
    buf = static_cast<struct statfs *>(vm->host_p(buf_p));
  }

  int res = vm->get_handlers()->statfs(path, buf);
  if(vm->debug_mode()) {
    DBG() << "STATFS path: " << LOG_GUEST_HOST(path_p, path)
          << " [" << std::string(path) << "]"
          << " buf: " << LOG_GUEST_HOST(buf_p, buf);
    Elkvm::dbg_log_result(res);
  }

  if(res == 0) {
    return 0;
  }
  return -errno;
}

long elkvm_do_fstatfs(Elkvm::VM * vm __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}
