#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <elkvm/elkvm.h>
#include <elkvm/syscall.h>

long elkvm_do_open(Elkvm::VM * vm) {
  if(vm->get_handlers()->open == nullptr) {
    ERROR() << "OPEN handler not found";
    return -ENOSYS;
  }

  CURRENT_ABI::paramtype pathname_p = 0x0;
  char *pathname = nullptr;
  CURRENT_ABI::paramtype flags = 0x0;
  CURRENT_ABI::paramtype mode = 0x0;

  vm->unpack_syscall(&pathname_p, &flags, &mode);
  assert(pathname_p != 0x0);

  pathname = static_cast<char *>(vm->host_p(pathname_p));

  long result = vm->get_handlers()->open(pathname,
      static_cast<int>(flags), static_cast<mode_t>(mode));

  if(vm->debug_mode()) {
    DBG() << "OPEN file " << LOG_GUEST_HOST(pathname_p, pathname)
          << " [" << pathname << "]"
          << " with flags 0x" << std::hex << flags
          << " mode 0x" << mode;
    Elkvm::dbg_log_result<int>(result);
  }

  return result;
}

long elkvm_do_openat(Elkvm::VM * vm) {
  if(vm->get_handlers()->openat == nullptr) {
    ERROR() << "OPENAT handler not found" << LOG_RESET << "\n";
    return -ENOSYS;
  }

  CURRENT_ABI::paramtype dirfd = 0;
  guestptr_t pathname_p = 0x0;
  CURRENT_ABI::paramtype flags = 0;

  vm->unpack_syscall(&dirfd, &pathname_p, &flags);

  char *pathname = nullptr;
  if(pathname_p != 0x0) {
    pathname = static_cast<char *>(vm->host_p(pathname_p));
  }

  int res = vm->get_handlers()->openat(static_cast<int>(dirfd),
      pathname, static_cast<int>(flags));
  if(vm->debug_mode()) {
    DBG() << "OPENAT with dirfd " << static_cast<int>(dirfd)
          << " pathname " << LOG_GUEST_HOST(pathname_p, pathname)
          << " [" << std::string(pathname) << "]"
          << " flags " << flags;
    if(dirfd == AT_FDCWD) {
      DBG() << "-> AT_FDCWD";
    }
    Elkvm::dbg_log_result(res);
  }

  if(res < 0) {
    return -errno;
  }

  return res;
}
