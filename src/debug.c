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

int elkvm_debug_bp_set(struct kvm_vcpu *vcpu, struct elkvm_sw_bp *bp) {
  assert(vcpu != NULL);
  assert(bp != NULL);

  static const uint8_t int3 = 0xcc;
  vcpu->debug.control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP;
  *bp->host_addr = int3;

  return elkvm_set_guest_debug(vcpu);
}

int elkvm_debug_breakpoint(struct kvm_vm *vm, struct kvm_vcpu *vcpu, uint64_t rip,
    int ignore_count) {
  assert(rip != 0x0);
  uint8_t *host_p = (uint8_t *)kvm_pager_get_host_p(&vm->pager, rip);
  assert(host_p != NULL);

  struct elkvm_sw_bp *bp = elkvm_bp_alloc(host_p, rip, ignore_count);
  if(bp == NULL) {
    return -ENOMEM;
  }

  int res = elkvm_debug_bp_set(vcpu, bp);
  if(res == 0) {
    list_push_front(vcpu->breakpoints, bp);
  }

  return res;
}

struct elkvm_sw_bp *elkvm_bp_alloc(uint8_t *host_p, uint64_t rip, int ignore_count) {
  struct elkvm_sw_bp *bp = malloc(sizeof(struct elkvm_sw_bp));
  if(bp == NULL) {
    return NULL;
  }

  bp->guest_virtual_addr = rip;
  bp->host_addr = host_p;
  bp->orig_inst = *host_p;
  bp->count = 0;
  bp->ignore_count = ignore_count;

  return bp;
}


int elkvm_set_guest_debug(struct kvm_vcpu *vcpu) {
  return ioctl(vcpu->fd, KVM_SET_GUEST_DEBUG, &vcpu->debug);
}

int elkvm_debug_shell(struct kvm_vm *vm) {
  char op;
  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

  while(op != 'x') {
    printf("\n");
    printf(" Please enter what to do, h for help\n");
    printf(" ===================================\n");
    printf(" > ");
    int items = scanf(" %c", &op);
    printf("\n");
    if(items == 0) {
      continue;
    }

    switch(op) {
      case 'h':
        printf("\ta\tAbort execution and exit shell\n");
        printf("\tx\tExit Shell and resume execution\n");
        printf("\tr\tDump registers, stack and code\n");
        printf("\ts\tStep to the next instruction\n");
        break;
      case 'a':
        return 1;
      case 'r':
        kvm_vcpu_dump_regs(vcpu);
        elkvm_dump_stack(vcpu->vm, vcpu);
			  kvm_vcpu_dump_code(vcpu);
        break;
      case 's':
        elkvm_debug_singlestep(vcpu);
        return 0;
      default:
        printf("Invalid command\n");
        break;
    }
  }

  return 0;

}

struct elkvm_sw_bp *elkvm_find_bp_for_rip(struct kvm_vcpu *vcpu, uint64_t rip) {
  list_each(vcpu->breakpoints, p) {
    if(p->guest_virtual_addr == vcpu->regs.rip) {
      return p;
    }
  }
  return NULL;
}

