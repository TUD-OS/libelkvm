#include <errno.h>
#include <string.h>

#include <elkvm.h>
#include <syscall.h>

int elkvm_handle_vm_shutdown(struct kvm_vm *vm, struct kvm_vcpu *vcpu) {
	int err = kvm_vcpu_get_regs(vcpu);
	if(err) {
		return 0;
	}

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
			fprintf(stderr, "Shutdown was syscall, handling...\n");
			int err = elkvm_handle_syscall(vm, vcpu);
			if(err) {
				return 0;
			}
		}

		/* TODO interrupts should be handled here */
		return 1;
	}

	return 0;
}

/* Taken from uClibc/libc/sysdeps/linux/x86_64/bits/syscalls.h
   The Linux/x86-64 kernel expects the system call parameters in                     
   registers according to the following table:                                       
                                                                                    
   syscall number  rax                                                              
   arg 1   rdi                                                                      
   arg 2   rsi                                                                      
   arg 3   rdx                                                                      
   arg 4   r10                                                                      
   arg 5   r8                                                                       
   arg 6   r9                                                                       
                                                                                    
   The Linux kernel uses and destroys internally these registers:                   
   return address from                                                              
   syscall   rcx                                                                    
   additionally clobered: r12-r15,rbx,rbp                                           
   eflags from syscall r11                                                          
                                                                                    
   Normal function call, including calls to the system call stub                    
   functions in the libc, get the first six parameters passed in                    
   registers and the seventh parameter and later on the stack.  The                 
   register use is as follows:                                                      
                                                                                    
    system call number in the DO_CALL macro                                         
    arg 1    rdi                                                                    
    arg 2    rsi                                                                    
    arg 3    rdx                                                                    
    arg 4    rcx                                                                    
    arg 5    r8                                                                     
    arg 6    r9                                                                     
                                                                                    
   We have to take care that the stack is aligned to 16 bytes.  When                
   called the stack is not aligned since the return address has just                
   been pushed.                                                                     
                                                                                    
                                                                                    
   Syscalls of more than 6 arguments are not supported.  */                         

int elkvm_handle_syscall(struct kvm_vm *vm, struct kvm_vcpu *vcpu) {
	uint64_t syscall_num = vcpu->regs.rax;

	long result;
	if(syscall_num > NUM_SYSCALLS) {
		result = ENOSYS;
	} else {
		result = elkvm_syscalls[syscall_num].func(vm);
	}
	/* binary expects syscall result in rax */
	vcpu->regs.rax = result;

	/* disable the trap flag */
	vcpu->regs.rflags = vcpu->regs.rflags & ~0x10100;

	/* restore the rip */
	//vcpu->regs.rip = vcpu->regs.rcx;
	/* vmxoff instruction is 3 bytes long */
	vcpu->regs.rip = vcpu->regs.rip + 0x3;

	int err = kvm_vcpu_set_regs(vcpu);
	return err;
}

int elkvm_syscall1(struct kvm_vm *vm, struct kvm_vcpu *vcpu, void **arg) {
	*arg = kvm_pager_get_host_p(&vm->pager, vcpu->regs.rdi);
	if(arg == NULL) {
		return -1;
	}
	return 0;
}

long elkvm_do_read(struct kvm_vm *vm) {
	return ENOSYS;
}

long elkvm_do_write(struct kvm_vm *vm) {
	return ENOSYS;
}

long elkvm_do_open(struct kvm_vm *vm) {
	return ENOSYS;
}

long elkvm_do_close(struct kvm_vm *vm) {
	return ENOSYS;
}

long elkvm_do_stat(struct kvm_vm *vm) {
	return ENOSYS;
}

long elkvm_do_fstat(struct kvm_vm *vm) {
	return ENOSYS;
}

long elkvm_do_lstat(struct kvm_vm *vm) {
	return ENOSYS;
}

long elkvm_do_poll(struct kvm_vm *vm) {
	return ENOSYS;
}

long elkvm_do_lseek(struct kvm_vm *vm) {
	return ENOSYS;
}

long elkvm_do_mmap(struct kvm_vm *vm) {
	return ENOSYS;
}

long elkvm_do_uname(struct kvm_vm *vm) {
	struct utsname *buf = NULL;
	int err = elkvm_syscall1(vm, vm->vcpus->vcpu, (void **)&buf);
	if(err) {
		return EIO;
	}

	return vm->syscall_handlers->uname(buf);
}
