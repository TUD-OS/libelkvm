#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <sys/ioctl.h>

#include <elkvm.h>
#include "debug.h"

int elkvm_handle_debug(struct kvm_vm *vm, struct kvm_vcpu *vcpu) {
  int handled = 0;
  if(vm->syscall_handlers->bp_callback != NULL) {
    handled = vm->syscall_handlers->bp_callback(vm);
  }

  return handled;
}

int elkvm_debug_enable(struct kvm_vcpu *vcpu) {
  vcpu->debug.control |= KVM_GUESTDBG_ENABLE;

  return elkvm_set_guest_debug(vcpu);
}

int elkvm_debug_singlestep(struct kvm_vcpu *vcpu) {
  vcpu->debug.control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP;
  vcpu->singlestep = 1;

  return elkvm_set_guest_debug(vcpu);
}

int elkvm_debug_singlestep_off(struct kvm_vcpu *vcpu) {
  vcpu->debug.control &= ~KVM_GUESTDBG_SINGLESTEP;
  vcpu->singlestep = 0;
  return elkvm_set_guest_debug(vcpu);
}

int elkvm_set_guest_debug(struct kvm_vcpu *vcpu) {
  return ioctl(vcpu->fd, KVM_SET_GUEST_DEBUG, &vcpu->debug);
}

