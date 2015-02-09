#include <elkvm/elkvm.h>
#include <elkvm/syscall.h>

#include <linux/futex.h>
#include <sys/types.h>

long elkvm_do_set_robust_list(Elkvm::VM *vm __attribute__((unused))) {
  if(vm->get_handlers()->set_robust_list == nullptr) {
    return -ENOSYS;
  }

  struct robust_list_head *head = nullptr;
  size_t len = 0x0;
  CURRENT_ABI::paramtype head_p = 0x0;

  vm->unpack_syscall(&head_p, &len);
  assert(head_p != 0x0);

  head = static_cast<struct robust_list_head *>(vm->host_p(head_p));
  long result = vm->get_handlers()->set_robust_list(head, len);
  if(vm->debug_mode()) {
    DBG() << "SET ROBUST LIST: head: " << LOG_GUEST_HOST(head_p, head)
          << " len: " << len;
    Elkvm::dbg_log_result<int>(result);
  }
  return result;
}

