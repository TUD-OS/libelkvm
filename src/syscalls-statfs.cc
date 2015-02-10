#include <sys/vfs.h>

#include <elkvm/elkvm.h>
#include <elkvm/syscall.h>

long elkvm_do_statfs(Elkvm::VM * vmi __attribute__((unused))) {
  if(vmi->get_handlers()->statfs == NULL) {
    INFO() <<"STATFS handler not found\n";
    return -ENOSYS;
  }

  guestptr_t path_p = 0x0;
  guestptr_t buf_p = 0x0;

  vmi->unpack_syscall(&path_p, &buf_p);

  char *path = NULL;
  struct statfs *buf = NULL;
  if(path_p != 0x0) {
    path = reinterpret_cast<char *>(vmi->get_region_manager()->get_pager().get_host_p(path_p));
  }
  if(buf_p != 0x0) {
    buf = reinterpret_cast<struct statfs *>(
        vmi->get_region_manager()->get_pager().get_host_p(buf_p));
  }

  int res = vmi->get_handlers()->statfs(path, buf);
  if(vmi->debug_mode()) {
    DBG() << "STATFS path " << LOG_GUEST_HOST(path_p, path)
          << " buf " << LOG_GUEST_HOST(buf_p, buf);
    DBG() << "RESULT: " << res << "\n";
  }

  if(res == 0) {
    return 0;
  }
  return -errno;
}

long elkvm_do_fstatfs(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}
