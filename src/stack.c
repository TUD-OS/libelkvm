#include <elkvm.h>
#include <pager.h>
#include <stack.h>
#include <vcpu.h>

uint16_t pop_stack(struct kvm_vm *vm, struct kvm_vcpu *vcpu) {
	int err = kvm_vcpu_get_regs(vcpu);
	if(err) {
		return err;
	}

	printf("got rsp: 0x%llx\n", vcpu->regs.rsp);
	uint16_t *host_p = (uint16_t *)kvm_pager_get_host_p(&vm->pager, vcpu->regs.rsp);
	printf("got host_p: %p\n", host_p);
	return *host_p;
}
