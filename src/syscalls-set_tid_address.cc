#include <elkvm/elkvm.h>
#include <elkvm/syscall.h>

long elkvm_do_set_tid_address(Elkvm::VM * vm) {
  if(vm->get_handlers()->set_tid_address == nullptr) {
    return -ENOSYS;
  }

  int *tidptr = nullptr;
  CURRENT_ABI::paramtype tidptr_p = 0x0;
  vm->unpack_syscall(&tidptr_p);
  assert(tidptr_p != 0x0);

  tidptr = static_cast<int *>(vm->host_p(tidptr_p));
  assert(tidptr != nullptr);
  long result = vm->get_handlers()->set_tid_address(tidptr);
  if(vm->debug_mode()) {
    DBG() << "SET TID ADDRESS tidptr at: " << LOG_GUEST_HOST(tidptr_p, tidptr);
    Elkvm::dbg_log_result(result);
  }

  return result;
}

