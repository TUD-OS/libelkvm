#include <elkvm/elkvm.h>
#include <elkvm/syscall.h>

long elkvm_do_sigaction(Elkvm::VM * vmi) {
  if(vmi->get_handlers()->sigaction == NULL) {
    ERROR() << "SIGACTION handler not found" << LOG_RESET << "\n";
    return -ENOSYS;
  }

  CURRENT_ABI::paramtype signum;
  CURRENT_ABI::paramtype act_p;
  CURRENT_ABI::paramtype oldact_p;

  vmi->unpack_syscall(&signum, &act_p, &oldact_p);

  struct sigaction *act = NULL;
  struct sigaction *oldact = NULL;
  if(act_p != 0x0) {
    act = reinterpret_cast<struct sigaction *>(vmi->get_region_manager()->get_pager().get_host_p(act_p));
  }
  if(oldact_p != 0x0) {
    oldact = reinterpret_cast<struct sigaction *>(vmi->get_region_manager()->get_pager().get_host_p(oldact_p));
  }

  int err = 0;
  if(vmi->get_handlers()->sigaction((int)signum, act, oldact)) {
    err = vmi->signal_register((int)signum, act, oldact);
  }

  if(vmi->debug_mode()) {
    DBG() << "SIGACTION with signum " << signum << " act " << (void*)act_p
          << " (" << (void*)act << ") oldact " << (void*)oldact_p << " (" << (void*)oldact << ")";
    if(err != 0) {
      DBG() << "ERROR: " << errno;
    }

  }

  return err;
}

long elkvm_do_sigprocmask(Elkvm::VM * vmi) {
  if(vmi->get_handlers()->sigprocmask == NULL) {
    ERROR() << "SIGPROCMASK handler not found" << LOG_RESET << "\n";
    return -ENOSYS;
  }

  CURRENT_ABI::paramtype how;
  CURRENT_ABI::paramtype set_p;
  CURRENT_ABI::paramtype oldset_p;

  vmi->unpack_syscall(&how, &set_p, &oldset_p);

  sigset_t *set = NULL;
  sigset_t *oldset = NULL;
  if(set_p != 0x0) {
    set = reinterpret_cast<sigset_t *>(vmi->get_region_manager()->get_pager().get_host_p(set_p));
  }
  if(oldset_p != 0x0) {
    oldset = reinterpret_cast<sigset_t *>(vmi->get_region_manager()->get_pager().get_host_p(oldset_p));
  }

  long result = vmi->get_handlers()->sigprocmask(how, set, oldset);
  if(vmi->debug_mode()) {
    DBG() << "RT SIGPROCMASK with how: " << how << " (" << (void*)&how << ") "
          << "set: " << (void*)set_p << " (" << (void*)set << ") "
          << "oldset: " << (void*)oldset_p << " (" << (void*)oldset;
    Elkvm::dbg_log_result<int>(result);
  }
  return result;
}


