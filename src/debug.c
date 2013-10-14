#include <sys/ioctl.h>

#include <elkvm.h>
#include "debug.h"

int elkvm_debug_enable(struct kvm_vcpu *vcpu) {
  vcpu->debug.control |= KVM_GUESTDBG_ENABLE;

  return elkvm_set_guest_debug(vcpu);
}

int elkvm_debug_singlestep(struct kvm_vcpu *vcpu) {
  vcpu->debug.control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP;
  vcpu->singlestep = 1;

  return elkvm_set_guest_debug(vcpu);
}

int elkvm_debug_breakpoint(struct kvm_vcpu *vcpu, uint64_t rip) {
  return -1;
}

int elkvm_set_guest_debug(struct kvm_vcpu *vcpu) {
  return ioctl(vcpu->fd, KVM_SET_GUEST_DEBUG, &vcpu->debug);
}

