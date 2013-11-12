#include <assert.h>
#include <errno.h>

#include <elkvm.h>
#include <pager.h>
#include <stack.h>
#include <vcpu.h>

uint64_t elkvm_popq(struct kvm_vm *vm, struct kvm_vcpu *vcpu) {
  assert(vcpu->regs.rsp != 0x0);
	uint64_t *host_p = kvm_pager_get_host_p(&vm->pager, vcpu->regs.rsp);
  assert(host_p != NULL);

	//vm->region[MEMORY_REGION_STACK].region_size -= 0x8;
	vcpu->regs.rsp += 0x8;

	return *host_p;
}

uint32_t elkvm_popd(struct kvm_vm *vm, struct kvm_vcpu *vcpu) {
  assert(vcpu->regs.rsp != 0x0);
  uint32_t *host_p = kvm_pager_get_host_p(&vm->pager, vcpu->regs.rsp);
  assert(host_p != NULL);

  vcpu->regs.rsp += 0x4;

  return *host_p;
}

int elkvm_pushq(struct kvm_vm *vm, struct kvm_vcpu *vcpu, uint64_t val) {
	//vm->region[MEMORY_REGION_STACK].region_size += 0x8;
	vcpu->regs.rsp -= 0x8;

  assert(vcpu->regs.rsp != 0x0);
	uint64_t *host_p = kvm_pager_get_host_p(&vm->pager, vcpu->regs.rsp);
	if(host_p == NULL) {
		/* current stack is full, we need to expand the stack */
		int err = expand_stack(vm, vcpu);
		if(err) {
			return err;
		}
		host_p = kvm_pager_get_host_p(&vm->pager, vcpu->regs.rsp);
		assert(host_p != NULL);
	}
	*host_p = val;

	return 0;
}

int expand_stack(struct kvm_vm *vm, struct kvm_vcpu *vcpu) {
  uint64_t oldrsp = page_begin(vm->current_user_stack->guest_virtual);
  uint64_t newrsp = oldrsp - ELKVM_PAGESIZE;

	struct elkvm_memory_region *region = elkvm_region_create(vm, ELKVM_PAGESIZE);
	if(region == NULL) {
		return -ENOMEM;
	}
	int err = kvm_pager_create_mapping(&vm->pager, region->host_base_p,
			newrsp, PT_OPT_WRITE);
  if(err) {
    return err;
  }

  region->guest_virtual = newrsp;
  vm->current_user_stack = region;
  return 0;
}

void elkvm_dump_stack(struct kvm_vm *vm, struct kvm_vcpu *vcpu) {
  assert(vcpu->regs.rsp != 0x0);
  uint64_t *host_p = kvm_pager_get_host_p(&vm->pager, vcpu->regs.rsp);
  uint64_t guest = vcpu->regs.rsp;

  fprintf(stderr, "\n");
  fprintf(stderr, " Stack:\n");
  fprintf(stderr, " ------\n");

  fprintf(stderr, " Host Address\tGuest Address\t\tValue\t\tValue\n");
  for(int i = 0; i < 6; i++) {
    fprintf(stderr, " %p\t0x%016lx\t0x%016lx\t0x%016lx\n",
        host_p, guest,
        *host_p, *(host_p+1));
    guest  += 0x10;
    host_p+=2;
  }
}
