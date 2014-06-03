#include <assert.h>
#include <errno.h>

#include <elkvm.h>
#include <pager.h>
#include <stack.h>
#include <vcpu.h>
#include "debug.h"

uint64_t elkvm_popq(struct kvm_vm *vm, struct kvm_vcpu *vcpu) {
  assert(vcpu->regs.rsp != 0x0);
	uint64_t *host_p = elkvm_pager_get_host_p(&vm->pager, vcpu->regs.rsp);
  assert(host_p != NULL);

	//vm->region[MEMORY_REGION_STACK].region_size -= 0x8;
	vcpu->regs.rsp += 0x8;

	return *host_p;
}

uint32_t elkvm_popd(struct kvm_vm *vm, struct kvm_vcpu *vcpu) {
  assert(vcpu->regs.rsp != 0x0);
  uint32_t *host_p = elkvm_pager_get_host_p(&vm->pager, vcpu->regs.rsp);
  assert(host_p != NULL);

  vcpu->regs.rsp += 0x4;

  return *host_p;
}

int elkvm_pushq(struct kvm_vm *vm, struct kvm_vcpu *vcpu, uint64_t val) {
	//vm->region[MEMORY_REGION_STACK].region_size += 0x8;
	vcpu->regs.rsp -= 0x8;

  assert(vcpu->regs.rsp != 0x0);
	uint64_t *host_p = elkvm_pager_get_host_p(&vm->pager, vcpu->regs.rsp);
	if(host_p == NULL) {
		/* current stack is full, we need to expand the stack */
		int err = elkvm_expand_stack(vm);
		if(err) {
			return err;
		}
		host_p = elkvm_pager_get_host_p(&vm->pager, vcpu->regs.rsp);
		assert(host_p != NULL);
	}
	*host_p = val;

	return 0;
}

int elkvm_expand_stack(struct kvm_vm *vm) {
  uint64_t oldrsp = 0;
  if(vm->current_user_stack == NULL) {
    oldrsp = page_begin(vm->env_region->guest_virtual);
  } else {
    oldrsp = page_begin(vm->current_user_stack->guest_virtual);
  }
  uint64_t newrsp = oldrsp - ELKVM_STACK_GROW;

	struct elkvm_memory_region *region = elkvm_region_create(ELKVM_STACK_GROW);
	if(region == NULL) {
		return -ENOMEM;
	}

  int err = elkvm_pager_map_region(&vm->pager, region->host_base_p, newrsp,
      ELKVM_STACK_GROW / ELKVM_PAGESIZE, PT_OPT_WRITE);
  if(err) {
    return err;
  }

  region->guest_virtual = newrsp;
  vm->current_user_stack = region;
  return 0;
}

bool elkvm_is_stack_expansion(struct kvm_vm *vm, guestptr_t pfla) {
  guestptr_t stack_top = page_begin(vm->current_user_stack->guest_virtual);
  if(pfla > stack_top) {
    return 0;
  }

  guestptr_t aligned_pfla = page_begin(pfla);
  uint64_t pages = pages_from_size(stack_top - aligned_pfla);

  /* TODO right now this is an arbitrary number... */
  return pages < 200;
}

void elkvm_dump_stack(struct kvm_vm *vm, struct kvm_vcpu *vcpu) {
  assert(vcpu->regs.rsp != 0x0);
  elkvm_dump_memory(vm, vcpu->regs.rsp);
}
