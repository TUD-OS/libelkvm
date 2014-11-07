#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <sys/ioctl.h>

#include <elkvm/elkvm.h>
#include <elkvm/elkvm-internal.h>
#include <elkvm/debug.h>

void Elkvm::VM::dump_memory(guestptr_t addr) {
  assert(addr != 0x0 && "cannot dump address NULL");
  uint64_t *host_p = reinterpret_cast<uint64_t *>(
  get_region_manager()->get_pager().get_host_p(addr));
  assert(host_p != NULL && "cannot dump unmapped memory");

  fprintf(stderr, " Host Address\tGuest Address\t\tValue\t\tValue\n");
  for(int i = 0; i < 16; i++) {
    fprintf(stderr, " %p\t0x%016lx\t0x%016lx\t0x%016lx\n",
            host_p, addr, *host_p, *(host_p+1));
    addr  += 0x10;
    host_p+=2;
  }
}

int elkvm_handle_debug(Elkvm::VM *vm) {
  int handled = 0;
  if(vm->get_handlers()->bp_callback != NULL) {
    handled = vm->get_handlers()->bp_callback(vm);
  }

  return handled;
}

int elkvm_debug_enable(std::shared_ptr<VCPU> vcpu) {
  vcpu->debug.control |= KVM_GUESTDBG_ENABLE;

  return vcpu->set_debug();
}

int elkvm_debug_singlestep(std::shared_ptr<VCPU> vcpu) {
  vcpu->debug.control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP;
  vcpu->singlestep = 1;

  return vcpu->set_debug();
}

int elkvm_debug_singlestep_off(std::shared_ptr<VCPU> vcpu) {
  vcpu->debug.control &= ~KVM_GUESTDBG_SINGLESTEP;
  vcpu->singlestep = 0;
  return vcpu->set_debug();
}

int VCPU::set_debug() {
  return ioctl(fd, KVM_SET_GUEST_DEBUG, &debug);
}
