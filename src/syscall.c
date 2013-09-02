#include <errno.h>
#include <string.h>
#include <asm/prctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>

#include <elkvm.h>
#include <heap.h>
#include <stack.h>
#include <syscall.h>
#include <vcpu.h>

int elkvm_handle_hypercall(struct kvm_vm *vm, struct kvm_vcpu *vcpu) {
	int err = kvm_vcpu_get_regs(vcpu);
	if(err) {
		return err;
	}

  int call = kvm_vcpu_get_hypercall_type(vm, vcpu);

  /* syscall */
		if(call == 1) {
			int err = elkvm_handle_syscall(vm, vcpu);
			if(err) {
				return err;
			}
      return 0;
    }

    /* interrupt */
    if(call == 2) {
      int err = elkvm_handle_interrupt(vm, vcpu);
      if(err) {
        return err;
      }

      return 0;
    }

    fprintf(stderr,
        "Hypercall was something else, don't know how to handle, ABORT!\n");
		/* TODO interrupts should be handled here */
    return 1;
}

int elkvm_handle_interrupt(struct kvm_vm *vm, struct kvm_vcpu *vcpu) {
  uint64_t interrupt_vector = elkvm_popq(vm, vcpu);

  printf(" INTERRUPT with vector 0x%lx detected\n", interrupt_vector);

  /* page fault */
	if(interrupt_vector == 0x0e) {
    uint32_t err_code = elkvm_popd(vm, vcpu);
    int err = kvm_pager_handle_pagefault(&vm->pager, vcpu->sregs.cr2, err_code);
    if(vcpu->sregs.cr2 == 0x0) {
      printf("\n\nABORT: SEGMENTATION FAULT\n\n");
      exit(1);
      return 1;
    }
		return 1;
	}

	return 1;
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
	uint64_t syscall_num = elkvm_popq(vm, vcpu);
  fprintf(stderr, " SYSCALL %3lu detected\n", syscall_num);

	long result;
	if(syscall_num > NUM_SYSCALLS) {
    fprintf(stderr, "\tINVALID syscall_num: %lu\n", syscall_num);
		result = -ENOSYS;
	} else {
    fprintf(stderr, "(%s)\n", elkvm_syscalls[syscall_num].name);
		result = elkvm_syscalls[syscall_num].func(vm);
	}
	/* binary expects syscall result in rax */
	vcpu->regs.rax = result;

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

int elkvm_syscall4(struct kvm_vm *vm, struct kvm_vcpu *vcpu,
		uint64_t *arg1, uint64_t *arg2, uint64_t *arg3, uint64_t *arg4) {
	*arg1 = vcpu->regs.rdi;
	*arg2 = vcpu->regs.rsi;
	*arg3 = vcpu->regs.rdx;
  *arg4 = vcpu->regs.r10;
	return 0;
}

int elkvm_syscall5(struct kvm_vm *vm, struct kvm_vcpu *vcpu,
		uint64_t *arg1, uint64_t *arg2, uint64_t *arg3, uint64_t *arg4,
    uint64_t *arg5) {
	*arg1 = vcpu->regs.rdi;
	*arg2 = vcpu->regs.rsi;
	*arg3 = vcpu->regs.rdx;
  *arg4 = vcpu->regs.r10;
  *arg5 = vcpu->regs.r8;
	return 0;
}

int elkvm_syscall6(struct kvm_vm *vm, struct kvm_vcpu *vcpu,
		uint64_t *arg1, uint64_t *arg2, uint64_t *arg3, uint64_t *arg4,
    uint64_t *arg5, uint64_t *arg6) {
	*arg1 = vcpu->regs.rdi;
	*arg2 = vcpu->regs.rsi;
	*arg3 = vcpu->regs.rdx;
  *arg4 = vcpu->regs.r10;
  *arg5 = vcpu->regs.r8;
  *arg6 = vcpu->regs.r9;
	return 0;
}

long elkvm_do_read(struct kvm_vm *vm) {
	if(vm->syscall_handlers->read == NULL) {
		printf("READ handler not found\n");
		return -ENOSYS;
	}

	uint64_t fd;
	uint64_t buf_p;
	char *buf;
	uint64_t count;

	int err = elkvm_syscall3(vm, vm->vcpus->vcpu, &fd, &buf_p, &count);
	if(err) {
		return -EIO;
	}

	buf = kvm_pager_get_host_p(&vm->pager, buf_p);
	printf("READ from fd: %i to %p with %zd bytes\n", (int)fd, buf, (size_t)count);

	long result = vm->syscall_handlers->read((int)fd, buf, (size_t)count);
	printf("RESULT (%li): %.*s\n", result, (int)result, buf);

	return result;
}

long elkvm_do_write(struct kvm_vm *vm) {
  if(vm->syscall_handlers->write == NULL) {
    printf("WRITE handler not found\n");
    return -ENOSYS;
  }

  uint64_t fd = 0x0;
  uint64_t buf_p = 0x0;
  void *buf;
  uint64_t count = 0x0;

  int err = elkvm_syscall3(vm, vm->vcpus->vcpu, &fd, &buf_p, &count);
  if(err) {
    return -EIO;
  }

  buf = kvm_pager_get_host_p(&vm->pager, buf_p);
  printf("WRITE to fd: %i from %p (guest: 0x%lx) with %zd bytes\n",
      (int)fd, buf, buf_p, (size_t)count);
	printf("\tDATA: %.*s\n", (int)count, (char *)buf);

  long result = vm->syscall_handlers->write((int)fd, buf, (size_t)count);
  printf("RESULT: %li\n", result);

  return result;
}

long elkvm_do_open(struct kvm_vm *vm) {
	if(vm->syscall_handlers->open == NULL) {
		printf("OPEN handler not found\n");
		return -ENOSYS;
	}

	uint64_t pathname_p = 0x0;
	char *pathname = NULL;
	uint64_t flags = 0x0;
	uint64_t mode = 0x0;

	int err = elkvm_syscall3(vm, vm->vcpus->vcpu, &pathname_p, &flags, &mode);
	if(err) {
		return -EIO;
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
		return -ENOSYS;
	}

	uint64_t fd = 0;
	int err = elkvm_syscall1(vm, vm->vcpus->vcpu, &fd);
	if(err) {
		return -EIO;
	}

	printf("CLOSE file with fd: %li\n", fd);
	long result = vm->syscall_handlers->close((int)fd);
	printf("RESULT: %li\n", result);

	return result;
}

long elkvm_do_stat(struct kvm_vm *vm) {
	return -ENOSYS;
}

long elkvm_do_fstat(struct kvm_vm *vm) {
  if(vm->syscall_handlers->fstat == NULL) {
    printf("FSTAT handler not found\n");
    return -ENOSYS;
  }

  uint64_t fd = 0;
  uint64_t buf_p = 0;
  struct stat *buf = NULL;
  int err = elkvm_syscall2(vm, vm->vcpus->vcpu, &fd, &buf_p);
  if(err) {
    return -EIO;
  }
	buf = kvm_pager_get_host_p(&vm->pager, buf_p);

  printf("FSTAT file with fd %li buf at %p\n", fd, buf);
  long result = vm->syscall_handlers->fstat(fd, buf);
  printf("RESULT: %li\n", result);
  return result;
}

long elkvm_do_lstat(struct kvm_vm *vm) {
	return -ENOSYS;
}

long elkvm_do_poll(struct kvm_vm *vm) {
	return -ENOSYS;
}

long elkvm_do_lseek(struct kvm_vm *vm) {
	return -ENOSYS;
}

long elkvm_do_mmap(struct kvm_vm *vm) {
  if(vm->syscall_handlers->mmap == NULL) {
    printf("MMAP handler not found\n");
    return -ENOSYS;
  }

  uint64_t addr_p = 0;
  void *addr = NULL;
  uint64_t length = 0;
  uint64_t prot = 0;
  uint64_t flags = 0;
  uint64_t fd = 0;
  uint64_t offset = 0;
  int err = elkvm_syscall6(vm, vm->vcpus->vcpu, &addr_p, &length, &prot, &flags,
      &fd, &offset);
  if(err) {
    return -EIO;
  }
  addr = kvm_pager_get_host_p(&vm->pager, addr_p);

  void *ret_p = NULL;
  long result = vm->syscall_handlers->mmap((void *)addr_p, length, prot,
      flags, fd, offset, &ret_p);
  struct kvm_userspace_memory_region *chunk =
    kvm_pager_alloc_chunk(&vm->pager, ret_p, length, 0);
  if(chunk == NULL) {
    return -ENOMEM;
  }
  err = kvm_vm_map_chunk(vm, chunk);
  if(err) {
    printf("ERROR mapping chunk %p\n", chunk);
    return err;
  }

  err = kvm_pager_create_mapping(&vm->pager, ret_p, (uint64_t)ret_p,
      flags & PROT_WRITE,
      flags & PROT_EXEC);
  printf("MAPPING from 0x%lx to %p created\n", (uint64_t) ret_p, ret_p);
  if(err) {
    printf("ERROR CREATING PT entries\n");
    return err;
  }

  return ret_p;
}

long elkvm_do_mprotect(struct kvm_vm *vm) {
	return -ENOSYS;
}

long elkvm_do_munmap(struct kvm_vm *vm) {
	return -ENOSYS;
}

long elkvm_do_brk(struct kvm_vm *vm) {
  uint64_t user_brk_req = 0;
  int err = elkvm_syscall1(vm, vm->vcpus->vcpu, &user_brk_req);
  printf("BRK reguested with address: 0x%lx\n", user_brk_req);
  if(err) {
    return -EIO;
  }

  /* if the requested brk address is 0 just return the current brk address */
  if(user_brk_req == 0) {
    printf("returning current brk address: 0x%lx\n", vm->pager.brk_addr);
    return vm->pager.brk_addr;
  }

  /* if the requested brk address is smaller than the current brk,
   * adjust the new brk */
  /* TODO free mapped pages, mark used regions as free, merge regions */
  if(user_brk_req < vm->pager.brk_addr) {
    printf("new brk (0x%lx) is smaller: 0x%lx\n", user_brk_req, vm->pager.brk_addr);
    vm->pager.brk_addr = user_brk_req;
    return user_brk_req;
  }

  /* if the requested brk address is still within the current data region,
   * just push the brk */
  err = elkvm_brk(vm, user_brk_req);
  printf("BRK done: err: %i (%s) newbrk: 0x%lx\n", err, strerror(err), vm->pager.brk_addr);
  if(err) {
    return err;
  }

  return vm->pager.brk_addr;
}

long elkvm_do_sigaction(struct kvm_vm *vm) {
  return -ENOSYS;
}

long elkvm_do_sigprocmask(struct kvm_vm *vm) {
  return -ENOSYS;
}

long elkvm_do_sigreturn(struct kvm_vm *vm) {
  return -ENOSYS;
}

long elkvm_do_ioctl(struct kvm_vm *vm) {
  return -ENOSYS;
}

long elkvm_do_pread64(struct kvm_vm *vm) {
  return -ENOSYS;
}

long elkvm_do_readv(struct kvm_vm *vm) {
  return -ENOSYS;
}

long elkvm_do_writev(struct kvm_vm *vm) {
  return -ENOSYS;
}

long elkvm_do_access(struct kvm_vm *vm) {
	if(vm->syscall_handlers->access == NULL) {
    printf("ACCESS handler not found\n");
		return -ENOSYS;
	}

  uint64_t path_p;
  uint64_t mode;

  int err = elkvm_syscall2(vm, vm->vcpus->vcpu, &path_p, &mode);
  if(err) {
    return err;
  }

  char *pathname = kvm_pager_get_host_p(&vm->pager, path_p);
  if(pathname == NULL) {
    return EFAULT;
  }
  printf("CALLING ACCESS handler with pathname %s and mode %i\n",
      pathname, (int)mode);

  long result = vm->syscall_handlers->access(pathname, mode);
  printf("ACCESS result: %li\n", result);

  return -errno;
}

long elkvm_do_uname(struct kvm_vm *vm) {
	if(vm->syscall_handlers->uname == NULL) {
		return -ENOSYS;
	}

	struct utsname *buf = NULL;
	uint64_t bufp = 0;
	int err = elkvm_syscall1(vm, vm->vcpus->vcpu, &bufp);
	if(err) {
		return -EIO;
	}
	buf = (struct utsname *)kvm_pager_get_host_p(&vm->pager, bufp);
	printf("CALLING UNAME handler with buf pointing to: %p (0x%lx)\n", buf,
			host_to_guest_physical(&vm->pager, buf));
	if(buf == NULL) {
		return -EIO;
	}

	long result = vm->syscall_handlers->uname(buf);
	result = 1;
	printf("UNAME result: %li\n", result);
	printf("\tsyname: %s nodename: %s release: %s version: %s machine: %s\n",
			buf->sysname, buf->nodename, buf->release, buf->version, buf->machine);
	return result;
}

long elkvm_do_getuid(struct kvm_vm *vm) {
	if(vm->syscall_handlers->getuid == NULL) {
		printf("GETUID handler not found\n");
		return -ENOSYS;
	}

	long result = vm->syscall_handlers->getuid();
	printf("GETUID RESULT: %li\n", result);

	return result;
}

long elkvm_do_syslog(struct kvm_vm *vm) {
  return -ENOSYS;
}

long elkvm_do_getgid(struct kvm_vm *vm) {
	if(vm->syscall_handlers->getgid == NULL) {
		printf("GETGID handler not found\n");
		return -ENOSYS;
	}

	long result = vm->syscall_handlers->getgid();
	printf("GETGID RESULT: %li\n", result);

	return result;
}

long elkvm_do_setuid(struct kvm_vm *vm) {
  return -ENOSYS;
}

long elkvm_do_setgid(struct kvm_vm *vm) {
  return -ENOSYS;
}

long elkvm_do_geteuid(struct kvm_vm *vm) {
	if(vm->syscall_handlers->geteuid == NULL) {
		printf("GETEUID handler not found\n");
		return -ENOSYS;
	}

	long result = vm->syscall_handlers->geteuid();
	printf("GETEUID RESULT: %li\n", result);

	return result;
}

long elkvm_do_getegid(struct kvm_vm *vm) {
	if(vm->syscall_handlers->getegid == NULL) {
		printf("GETEGID handler not found\n");
		return -ENOSYS;
	}

	long result = vm->syscall_handlers->getegid();
	printf("GETEGID RESULT: %li\n", result);

	return result;
}

long elkvm_do_arch_prctl(struct kvm_vm *vm) {
  uint64_t code = 0;
  uint64_t user_addr = 0;
  int err = elkvm_syscall2(vm, vm->vcpus->vcpu, &code, &user_addr);
  if(err) {
    return err;
  }
  uint64_t *host_addr = kvm_pager_get_host_p(&vm->pager, user_addr);
  if(host_addr == NULL) {
    return EFAULT;
  }

  printf("ARCH PRCTL with code %i user_addr 0x%lx\n", (int)code, user_addr);
  struct kvm_vcpu *vcpu = vm->vcpus->vcpu;
  switch(code) {
    case ARCH_SET_FS:
      printf("SET FS to 0x%lx\n", user_addr);
      vcpu->sregs.fs.base = user_addr;
      break;
    case ARCH_GET_FS:
      printf("GET FS to buf at %p\n", host_addr);
      *host_addr = vcpu->sregs.fs.base;
      break;
    case ARCH_SET_GS:
      printf("SET GS to 0x%lx\n", user_addr);
      vcpu->sregs.gs.base = user_addr;
      break;
    case ARCH_GET_GS:
      printf("GET GS to buf at %p\n", host_addr);
      *host_addr = vcpu->sregs.gs.base;
      break;
    default:
      return EINVAL;
  }

  return 0;
}

long elkvm_do_exit_group(struct kvm_vm *vm) {
  uint64_t status = 0;
  int err = elkvm_syscall1(vm, vm->vcpus->vcpu, &status);
  if(err) {
    return err;
  }

  vm->syscall_handlers->exit_group(status);
  /* should not be reached... */
  return -ENOSYS;
}

