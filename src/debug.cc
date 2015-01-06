#include <assert.h>
#include <errno.h>
#include <iomanip>
#include <iostream>
#include <sys/ioctl.h>

#include <elkvm/elkvm.h>
#include <elkvm/elkvm-internal.h>
#include <elkvm/debug.h>
#include <elkvm/vcpu.h>

int elkvm_handle_debug(Elkvm::VM *vm) {
  int handled = 0;
  if(vm->get_handlers()->bp_callback != NULL) {
    handled = vm->get_handlers()->bp_callback(vm);
  }

  return handled;
}

namespace Elkvm {

std::ostream &print_memory(std::ostream &os, const VM &vm, guestptr_t addr,
    size_t size) {
  assert(addr != 0x0 && "cannot dump address NULL");
  uint64_t *host_p = static_cast<uint64_t *>(
      vm.get_region_manager()->get_pager().get_host_p(addr));
  assert(host_p != nullptr && "cannot dump unmapped memory");

  os << " Host Address\tGuest Address\t\tValue\t\t\tValue\n";
  for(unsigned i = 0; i < size; i++) {
    os << std::hex
      << " " << host_p
      << " 0x" << addr
      << "\t0x" << std::setw(16) << std::setfill('0') << *host_p
      << "\t0x" << std::setw(16) << std::setfill('0') << *(host_p + 1) << std::endl;
    addr  += 0x10;
    host_p+=2;
  }

  return os;
}

int VCPU::enable_debug() {
  return _kvm_vcpu.enable_debug();
}

int VCPU::singlestep() {
  is_singlestepping = true;
  return _kvm_vcpu.singlestep();
}

int VCPU::singlestep_off() {
  is_singlestepping = false;
  return _kvm_vcpu.singlestep_off();
}

int VCPU::enable_software_breakpoints() {
  return _kvm_vcpu.enable_software_breakpoints();
}

namespace KVM {

int VCPU::enable_debug() {
  debug.control |= KVM_GUESTDBG_ENABLE;
  return set_debug();
}

int VCPU::singlestep() {
  debug.control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP;
  return set_debug();
}

int VCPU::singlestep_off() {
  debug.control &= ~KVM_GUESTDBG_SINGLESTEP;
  return set_debug();
}

int VCPU::set_debug() {
  return ioctl(fd, KVM_SET_GUEST_DEBUG, &debug);
}

int VCPU::enable_software_breakpoints() {
  debug.control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP;
  return set_debug();
}

//namespace KVM
}
//namespace Elkvm
}
