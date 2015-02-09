#include <elkvm/elkvm.h>

long elkvm_do_getrlimit(Elkvm::VM *) {
  /* XXX implement again! */
    UNIMPLEMENTED_SYSCALL;
//  CURRENT_ABI::paramtype resource = 0x0;
//  CURRENT_ABI::paramtype rlim_p = 0x0;
//  struct rlimit *rlim = NULL;
//
//  vmi->unpack_syscall(&resource, &rlim_p);
//
//  assert(rlim_p != 0x0);
//  rlim = reinterpret_cast<struct rlimit *>(vmi->get_region_manager()->get_pager().get_host_p(rlim_p));
//
//  memcpy(rlim, &vm->rlimits[resource], sizeof(struct rlimit));
//  if(vmi->debug_mode()) {
//    printf("GETRLIMIT with resource: %li rlim: 0x%lx (%p)\n",
//        resource, rlim_p, rlim);
//  }
//
//  return 0;
}

