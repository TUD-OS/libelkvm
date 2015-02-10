#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <elkvm/elkvm.h>
#include <elkvm/syscall.h>

long elkvm_do_open(Elkvm::VM * vmi) {
  if(vmi->get_handlers()->open == NULL) {
    ERROR() << "OPEN handler not found\n";
    return -ENOSYS;
  }

  CURRENT_ABI::paramtype pathname_p = 0x0;
  char *pathname = NULL;
  CURRENT_ABI::paramtype flags = 0x0;
  CURRENT_ABI::paramtype mode = 0x0;

  vmi->unpack_syscall(&pathname_p, &flags, &mode);

  assert(pathname_p != 0x0);
  pathname = reinterpret_cast<char *>(vmi->get_region_manager()->get_pager().get_host_p(pathname_p));

  long result = vmi->get_handlers()->open(pathname, (int)flags, (mode_t)mode);

  if(vmi->debug_mode()) {
    DBG() << "OPEN file " << pathname << " with flags " << std::hex
          << flags << " and mode " << mode << std::dec;
    Elkvm::dbg_log_result<int>(result);
  }

  return result;
}

long elkvm_do_openat(Elkvm::VM * vmi) {
  if(vmi->get_handlers()->openat == NULL) {
    ERROR() << "OPENAT handler not found" << LOG_RESET << "\n";
    return -ENOSYS;
  }

  CURRENT_ABI::paramtype dirfd = 0;
  guestptr_t pathname_p = 0x0;
  CURRENT_ABI::paramtype flags = 0;

  vmi->unpack_syscall(&dirfd, &pathname_p, &flags);

  char *pathname = nullptr;
  if(pathname_p != 0x0) {
    pathname = static_cast<char *>(vmi->host_p(pathname_p));
  }

  int res = vmi->get_handlers()->openat((int)dirfd, pathname, (int)flags);
  if(vmi->debug_mode()) {
    DBG() << "OPENAT with dirfd " << static_cast<int>(dirfd)
          << " pathname " << LOG_GUEST_HOST(pathname_p, pathname)
          << " [" << std::string(pathname) << "]"
          << " flags " << flags;
    if(dirfd == AT_FDCWD) {
      DBG() << "-> AT_FDCWD";
    }
    DBG() << "RESULT: " << res << "\n";
  }

  if(res < 0) {
    return -errno;
  }

  return res;
}

