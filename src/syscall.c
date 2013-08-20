#include <errno.h>
#include <string.h>

#include <elkvm.h>
#include <syscall.h>
#include <vcpu.h>

int elkvm_handle_vm_shutdown(struct kvm_vm *vm, struct kvm_vcpu *vcpu) {
	int err = kvm_vcpu_get_regs(vcpu);
	if(err) {
		return 0;
	}

	if(kvm_vcpu_had_page_fault(vcpu)) {
		void *host_p = kvm_pager_get_host_p(&vm->pager, vcpu->sregs.cr2);
		if(host_p != NULL) {
			kvm_pager_dump_page_tables(&vm->pager);
			printf("\n Invalid");
		}
		printf(" Page Fault:\n");
		printf(" -------------------\n");
		printf("PFLA: 0x%llx\n", vcpu->sregs.cr2);
		printf("Should result in host virtual: %p\n", host_p);
		uint64_t page_off = vcpu->sregs.cr2 & 0xFFF;
		uint64_t pt_off   = (vcpu->sregs.cr2 >> 12) & 0x1FF;
		uint64_t pd_off   = (vcpu->sregs.cr2 >> 21) & 0x1FF;
		uint64_t pdpt_off = (vcpu->sregs.cr2 >> 30) & 0x1FF;
		uint64_t pml4_off = (vcpu->sregs.cr2 >> 39) & 0x1FF;
		printf("Offsets: pml4: %lu pdpt: %lu pd: %lu pt: %lu page: %lu\n",
				pml4_off, pdpt_off, pd_off, pt_off, page_off);
		printf("Check CPL and Writeable bits!\n");

		return 0;
	}

	if(kvm_vcpu_did_hypercall(vm, vcpu)) {
		if(kvm_vcpu_did_syscall(vm, vcpu)) {
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
	printf("syscall_num: %li (%s)\n", syscall_num, elkvm_syscalls[syscall_num].name);

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

	/* vmxoff instruction is 3 bytes long */
	vcpu->regs.rip = vcpu->regs.rip + 0x3;

	int err = kvm_vcpu_set_regs(vcpu);
	return err;
}

int elkvm_syscall1(struct kvm_vm *vm, struct kvm_vcpu *vcpu, uint64_t *arg) {
	*arg = vcpu->regs.rdi;
	return 0;
}

int elkvm_syscall2(struct kvm_vm *vm, struct kvm_vcpu *vcpu,
		uint64_t *arg1, uint64_t *arg2) {
	*arg1 = vcpu->regs.rdi;
	*arg2 = vcpu->regs.rsi;
	return 0;
}

int elkvm_syscall3(struct kvm_vm *vm, struct kvm_vcpu *vcpu,
		uint64_t *arg1, uint64_t *arg2, uint64_t *arg3) {
	*arg1 = vcpu->regs.rdi;
	*arg2 = vcpu->regs.rsi;
	*arg3 = vcpu->regs.rdx;
	return 0;
}

long elkvm_do_read(struct kvm_vm *vm) {
	if(vm->syscall_handlers->read == NULL) {
		printf("READ handler not found\n");
		return ENOSYS;
	}

	uint64_t fd;
	uint64_t buf_p;
	char *buf;
	uint64_t count;

	int err = elkvm_syscall3(vm, vm->vcpus->vcpu, &fd, &buf_p, &count);
	if(err) {
		return EIO;
	}

	buf = kvm_pager_get_host_p(&vm->pager, buf_p);
	printf("READ from fd: %i to %p with %zd bytes\n", (int)fd, buf, (size_t)count);

	long result = vm->syscall_handlers->read((int)fd, buf, (size_t)count);
	printf("RESULT (%li): %.*s\n", result, (int)result, buf);

	return result;
}

long elkvm_do_write(struct kvm_vm *vm) {
	return ENOSYS;
}

long elkvm_do_open(struct kvm_vm *vm) {
	if(vm->syscall_handlers->open == NULL) {
		printf("OPEN handler not found\n");
		return ENOSYS;
	}

	uint64_t pathname_p = 0x0;
	char *pathname = NULL;
	uint64_t flags = 0x0;
	uint64_t mode = 0x0;

	int err = elkvm_syscall3(vm, vm->vcpus->vcpu, &pathname_p, &flags, &mode);
	if(err) {
		return EIO;
	}
	pathname = kvm_pager_get_host_p(&vm->pager, pathname_p);

	printf("OPEN file %s with flags %i and mode %x\n", pathname,
			(int)flags, (mode_t)mode);
	long result = vm->syscall_handlers->open(pathname, (int)flags, (mode_t)mode);
	printf("RESULT: %li\n", result);

	return result;
}

long elkvm_do_close(struct kvm_vm *vm) {
	if(vm->syscall_handlers->close == NULL) {
		printf("CLOSE handler not found\n");
		return ENOSYS;
	}

	uint64_t fd = 0;
	int err = elkvm_syscall1(vm, vm->vcpus->vcpu, &fd);
	if(err) {
		return EIO;
	}

	printf("CLOSE file with fd: %li\n", fd);
	long result = vm->syscall_handlers->close((int)fd);
	printf("RESULT: %li\n", result);

	return result;
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

long elkvm_do_mprotect(struct kvm_vm *vm) {
	return ENOSYS;
}

long elkvm_do_munmap(struct kvm_vm *vm) {
	return ENOSYS;
}

long elkvm_do_brk(struct kvm_vm *vm) {
  uint64_t user_brk_req = 0;
  int err = elkvm_syscall1(vm, vm->vcpus->vcpu, &user_brk_req);
  printf("BRK reguested with address: 0x%lx\n", user_brk_req);
  if(err) {
    return EIO;
  }

  /* if the requested brk address is 0 just return the current brk address */
  if(user_brk_req == 0) {
    printf("returning current brk address: 0x%lx\n", vm->pager.brk_addr);
    return vm->pager.brk_addr;
  }

  /* if the requested brk address is smaller than the current brk,
   * adjust the new brk */
  if(user_brk_req < vm->pager.brk_addr) {
    printf("new brk (0x%lx) is smaller: 0x%lx\n", user_brk_req, vm->pager.brk_addr);
    vm->pager.brk_addr = user_brk_req;
    return user_brk_req;
  }

  /* if the requested brk address is still within the current data region,
   * just push the brk */
  if(user_brk_req < (vm->data->guest_virtual + vm->data->region_size)) {
    printf("new brk (0x%lx) is larger, but fits in region: 0x%lx (0x%lx)\n",
        user_brk_req, vm->data->guest_virtual, vm->data->region_size);
    vm->pager.brk_addr = user_brk_req;
    return user_brk_req;
  }

  /* if the requested brk does not fit in the current memory region,
   * check if limits are held, and request more memory */
  printf("new brk (0x%lx) does not fit in data region: 0x%lx (0x%lx)\n",
      user_brk_req, vm->data->guest_virtual, vm->data->region_size);
  printf("return old brk 0x%lx\n", vm->pager.brk_addr);
  return vm->pager.brk_addr;
}

long elkvm_do_uname(struct kvm_vm *vm) {
	if(vm->syscall_handlers->uname == NULL) {
		return ENOSYS;
	}

	struct utsname *buf = NULL;
	uint64_t bufp = 0;
	int err = elkvm_syscall1(vm, vm->vcpus->vcpu, &bufp);
	if(err) {
		return EIO;
	}
	buf = (struct utsname *)kvm_pager_get_host_p(&vm->pager, bufp);
	printf("CALLING UNAME handler with buf pointing to: %p (0x%lx)\n", buf,
			host_to_guest_physical(&vm->pager, buf));
	if(buf == NULL) {
		return EIO;
	}

	long result = vm->syscall_handlers->uname(buf);
	result = 1;
	printf("UNAME result: %li\n", result);
	printf("\tsyname: %s nodename: %s release: %s version: %s machine: %s\n",
			buf->sysname, buf->nodename, buf->release, buf->version, buf->machine);
	return result;
}

