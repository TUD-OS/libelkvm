#include <assert.h>
#include <errno.h>

#include <elkvm.h>
#include <pager.h>
#include <stack.h>
#include <vcpu.h>

uint16_t pop_stack(struct kvm_vm *vm, struct kvm_vcpu *vcpu) {
	int err = kvm_vcpu_get_regs(vcpu);
	assert(err == 0);

	uint16_t *host_p = (uint16_t *)kvm_pager_get_host_p(&vm->pager, vcpu->regs.rsp);

	//vm->region[MEMORY_REGION_STACK].region_size -= 0x8;
	vcpu->regs.rsp += 0x8;
	err = kvm_vcpu_set_regs(vcpu);
	assert(err == 0);

	return *host_p;
}

int push_stack(struct kvm_vm *vm, struct kvm_vcpu *vcpu, uint16_t val) {
	int err = kvm_vcpu_get_regs(vcpu);
	if(err < 0) {
		return err;
	}

	//vm->region[MEMORY_REGION_STACK].region_size += 0x8;
	vcpu->regs.rsp -= 0x8;

	uint16_t *host_p = kvm_pager_get_host_p(&vm->pager, vcpu->regs.rsp);
	if(host_p == NULL) {
		/* current stack is full, we need to expand the stack */
		err = expand_stack(vm, vcpu);
		if(err) {
			return err;
		}
		host_p = kvm_pager_get_host_p(&vm->pager, vcpu->regs.rsp);
		assert(host_p != NULL);
	}
	*host_p = val;

	err = kvm_vcpu_set_regs(vcpu);
	return err;
}

int expand_stack(struct kvm_vm *vm, struct kvm_vcpu *vcpu) {
	struct elkvm_memory_region *region = elkvm_region_create(vm, 0x1000);
	if(region == NULL) {
		return -ENOMEM;
	}
	int err = kvm_pager_create_mapping(&vm->pager, region->host_base_p,
			vcpu->regs.rsp & ~0xFFF, 1, 0);
	return err;
}
