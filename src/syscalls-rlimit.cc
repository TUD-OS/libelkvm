#include <elkvm/elkvm.h>

#include <sys/time.h>
#include <sys/resource.h>

long elkvm_do_getrlimit(Elkvm::VM *vm) {
  CURRENT_ABI::paramtype resource = 0x0;
  CURRENT_ABI::paramtype rlim_p = 0x0;
  struct rlimit *rlim = NULL;

  vm->unpack_syscall(&resource, &rlim_p);

  assert(rlim_p != 0x0);
  rlim = static_cast<struct rlimit *>(vm->host_p(rlim_p));

  memcpy(rlim, vm->get_rlimit(resource), sizeof(struct rlimit));
  if(vm->debug_mode()) {
    DBG() << "GETRLIMIT with resource: " << std::dec << resource
          << " rlim: " << LOG_GUEST_HOST(rlim_p, rlim);
  }

  return 0;
}

long elkvm_do_setrlimit(Elkvm::VM * vm) {
  if(vm->get_handlers()->setrlimit == nullptr) {
    return -ENOSYS;
  }

  CURRENT_ABI::paramtype resource = 0x0;
  CURRENT_ABI::paramtype rlim_p = 0x0;
  const struct rlimit *rlim = nullptr;

  vm->unpack_syscall(&resource, &rlim_p);
  assert(rlim_p != 0x0);

  rlim = static_cast<const struct rlimit *>(vm->host_p(rlim_p));

  int err = vm->get_handlers()->setrlimit(resource, rlim);
  if(err == 0) {
    vm->set_rlimit(resource, rlim);
  }

  if(vm->debug_mode()) {
    DBG() << "GETRLIMIT with resource: " << std::dec << resource
          << " rlim: " << LOG_GUEST_HOST(rlim_p, rlim);
    Elkvm::dbg_log_result<int>(err);
  }
  return err;
}
