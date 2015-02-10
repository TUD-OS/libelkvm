#include <elkvm/elkvm.h>
#include <elkvm/syscall.h>

#include <time.h>

long elkvm_do_clock_gettime(Elkvm::VM * vmi) {
  if(vmi->get_handlers()->clock_gettime == NULL) {
    ERROR() << "CLOCK GETTIME handler not found" << LOG_RESET << "\n";
    return -ENOSYS;
  }

  CURRENT_ABI::paramtype clk_id = 0x0;
  CURRENT_ABI::paramtype tp_p = 0x0;
  struct timespec *tp = NULL;

  vmi->unpack_syscall(&clk_id, &tp_p);
  assert(tp_p != 0x0);

  tp = reinterpret_cast<struct timespec *>(vmi->get_region_manager()->get_pager().get_host_p(tp_p));
  assert(tp != NULL);

  long result = vmi->get_handlers()->clock_gettime(clk_id, tp);
  if(vmi->debug_mode()) {
    DBG() << "CLOCK GETTIME with clk_id " << clk_id << " tp " << LOG_GUEST_HOST(tp_p, tp);
    Elkvm::dbg_log_result<int>(result);
  }
  return result;
}

long elkvm_do_clock_getres(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}
