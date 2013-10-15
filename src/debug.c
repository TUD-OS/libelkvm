#include <assert.h>
#include <errno.h>
#include <sys/ioctl.h>

#include <elkvm.h>
#include "debug.h"

int elkvm_handle_debug(struct kvm_vm *vm, struct kvm_vcpu *vcpu) {
  uint8_t *host_p = (uint8_t *)kvm_pager_get_host_p(&vm->pager, vcpu->regs.rip);
  assert(host_p != NULL);

  struct elkvm_sw_bp *bp;
  list_each(vcpu->breakpoints, p) {
    if(p->guest_virtual_addr == vcpu->regs.rip) {
      bp = p;
    }
  }

  *host_p = bp->orig_inst;
  bp->count++;

  printf("Hit Breakpoint %p the %ith time\n", bp, bp->count);

 return -1;
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

int elkvm_debug_breakpoint(struct kvm_vm *vm, struct kvm_vcpu *vcpu, uint64_t rip) {
  static const uint8_t int3 = 0xcc;

  vcpu->debug.control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP;

  uint8_t *host_p = (uint8_t *)kvm_pager_get_host_p(&vm->pager, rip);
  assert(host_p != NULL);

  struct elkvm_sw_bp *bp = malloc(sizeof(struct elkvm_sw_bp));
  if(bp == NULL) {
    return -ENOMEM;
  }

  bp->guest_virtual_addr = rip;
  bp->orig_inst = *host_p;
  bp->count = 0;

  *host_p = int3;
  list_push_front(vcpu->breakpoints, bp);

  return elkvm_set_guest_debug(vcpu);
}

int elkvm_set_guest_debug(struct kvm_vcpu *vcpu) {
  return ioctl(vcpu->fd, KVM_SET_GUEST_DEBUG, &vcpu->debug);
}

