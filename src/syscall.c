#include <string.h>

#include <syscall.h>

int elkvm_handle_vm_shutdown(struct kvm_vm *vm, struct kvm_vcpu *vcpu) {

	char *host_rip_p = (char *)kvm_pager_get_host_p(&vm->pager, vcpu->regs.rip);

	const char vmxoff[3] = { 0x0F, 0x01, 0xC4 };
	const char syscall[2] = { 0x0F, 0x05 };

	/* check if the guest explicitly called for the vmm */
	if(memcmp(host_rip_p, vmxoff, 3) == 0) {
		/* 
		 * on syscall the instruction after the syscall is stored in rcx
		 * also, syscall is 2 bytes long
		 */
		host_rip_p = kvm_pager_get_host_p(&vm->pager, vcpu->regs.rcx - 0x2);
		if(memcmp(host_rip_p, syscall, 2) == 0) {
			int err = elkvm_handle_syscall(vm);
			if(err) {
				return 0;
			}
		}

		/* TODO interrupts should be handled here */
		return 1;
	}

	return 0;
}

int elkvm_handle_syscall(struct kvm_vm *vcpu) {
	uint64_t syscall_num = vcpu->regs.rax;
	if(syscall_num > NUM_SYSCALLS) {
		/* TODO probably set rax here */
		return -ENOSYS;
	}

	int err = elkvm_syscalls[syscall_num].func(vcpu);
	return err;
}

long elkvm_do_read(struct kvm_vm *vcpu) {
	return -1;
}

long elkvm_do_uname(struct kvm_vm *vcpu) {
	return -1;
}
