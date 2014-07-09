#include <cstring>
#include <iostream>

#include <errno.h>
#include <asm-generic/fcntl.h>
#include <asm/prctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/times.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <elkvm.h>
#include <elkvm-internal.h>
#include <heap.h>
#include <mapping.h>
#include <stack.h>
#include <syscall.h>
#include <vcpu.h>

#include "elfloader.h"
#include "region.h"

namespace Elkvm {
  extern Stack stack;
  extern std::unique_ptr<VMInternals> vmi;
}

int elkvm_handle_hypercall(struct kvm_vm *vm, std::shared_ptr<struct kvm_vcpu> vcpu) {
  int err = 0;

  uint64_t call = kvm_vcpu_get_hypercall_type(vm, vcpu.get());
  switch(call) {
    case ELKVM_HYPERCALL_SYSCALL:
			err = elkvm_handle_syscall(vm, vcpu.get());
      break;
    case ELKVM_HYPERCALL_INTERRUPT:
      err = elkvm_handle_interrupt(vm, vcpu.get());
      if(err) {
        return err;
      }
      break;
    default:
      fprintf(stderr,
          "Hypercall was something else, don't know how to handle, ABORT!\n");
      return 1;
  }

	if(err) {
		return err;
	}

  elkvm_emulate_vmcall(vcpu.get());

  err = elkvm_signal_deliver(vm);
  assert(err == 0);

  return 0;
}

int elkvm_handle_interrupt(struct kvm_vm *vm, struct kvm_vcpu *vcpu) {
  uint64_t interrupt_vector = Elkvm::stack.popq();

  if(vm->debug) {
    printf(" INTERRUPT with vector 0x%lx detected\n", interrupt_vector);
    kvm_vcpu_get_sregs(vcpu);
    kvm_vcpu_dump_regs(vcpu);
    Elkvm::dump_stack(vm, vcpu);
  }

  /* Stack Segment */
  if(interrupt_vector == 0x0c) {
    uint64_t err_code = Elkvm::stack.popq();
    printf("STACK SEGMENT FAULT\n");
    printf("Error Code: %lu\n", err_code);
    return 1;
  }

  /* General Protection */
  if(interrupt_vector == 0x0d) {
    uint64_t err_code = Elkvm::stack.popq();
    printf("GENERAL PROTECTION FAULT\n");
    printf("Error Code: %lu\n", err_code);
    return 1;

  }

  /* page fault */
	if(interrupt_vector == 0x0e) {
    int err = kvm_vcpu_get_sregs(vcpu);
    if(err) {
      return err;
    }

    if(vcpu->sregs.cr2 == 0x0) {
      printf("\n\nABORT: SEGMENTATION FAULT\n\n");
      exit(1);
      return 1;
    }

    uint32_t err_code = Elkvm::stack.popq();
    err = Elkvm::vmi->get_region_manager().get_pager().handle_pagefault(vcpu->sregs.cr2, err_code,
        vm->debug);

		return err;
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
	uint64_t syscall_num = vcpu->regs.rax;
  if(vm->debug) {
    fprintf(stderr, " SYSCALL %3lu detected\n", syscall_num);
  }

	long result;
	if(syscall_num > NUM_SYSCALLS) {
    fprintf(stderr, "\tINVALID syscall_num: %lu\n", syscall_num);
		result = -ENOSYS;
	} else {
    if(vm->debug) {
      fprintf(stderr, "(%s)\n", elkvm_syscalls[syscall_num].name);
    }
		result = elkvm_syscalls[syscall_num].func(vm);
    if(syscall_num == __NR_exit_group) {
      return ELKVM_HYPERCALL_EXIT;
    }
	}
	/* binary expects syscall result in rax */
	vcpu->regs.rax = result;

	return 0;
}

void elkvm_syscall1(struct kvm_vcpu *vcpu, uint64_t *arg) {
	*arg = vcpu->regs.rdi;
}

void elkvm_syscall2(struct kvm_vcpu *vcpu,
		uint64_t *arg1, uint64_t *arg2) {
	*arg1 = vcpu->regs.rdi;
	*arg2 = vcpu->regs.rsi;
}

void elkvm_syscall3(struct kvm_vcpu *vcpu,
		uint64_t *arg1, uint64_t *arg2, uint64_t *arg3) {
	*arg1 = vcpu->regs.rdi;
	*arg2 = vcpu->regs.rsi;
	*arg3 = vcpu->regs.rdx;
}

void elkvm_syscall4(struct kvm_vcpu *vcpu,
		uint64_t *arg1, uint64_t *arg2, uint64_t *arg3, uint64_t *arg4) {
	*arg1 = vcpu->regs.rdi;
	*arg2 = vcpu->regs.rsi;
	*arg3 = vcpu->regs.rdx;
  *arg4 = vcpu->regs.r10;
}

void elkvm_syscall5(struct kvm_vcpu *vcpu,
		uint64_t *arg1, uint64_t *arg2, uint64_t *arg3, uint64_t *arg4,
    uint64_t *arg5) {
	*arg1 = vcpu->regs.rdi;
	*arg2 = vcpu->regs.rsi;
	*arg3 = vcpu->regs.rdx;
  *arg4 = vcpu->regs.r10;
  *arg5 = vcpu->regs.r8;
}

void elkvm_syscall6(struct kvm_vcpu *vcpu,
		uint64_t *arg1, uint64_t *arg2, uint64_t *arg3, uint64_t *arg4,
    uint64_t *arg5, uint64_t *arg6) {
	*arg1 = vcpu->regs.rdi;
	*arg2 = vcpu->regs.rsi;
	*arg3 = vcpu->regs.rdx;
  *arg4 = vcpu->regs.r10;
  *arg5 = vcpu->regs.r8;
  *arg6 = vcpu->regs.r9;
}

long elkvm_do_read(struct kvm_vm *vm) {
	if(vm->syscall_handlers->read == NULL) {
		printf("READ handler not found\n");
		return -ENOSYS;
	}
  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

	uint64_t fd;
	uint64_t buf_p;
	char *buf;
	uint64_t count;

	elkvm_syscall3(vcpu, &fd, &buf_p, &count);

  assert(buf_p != 0x0);
	buf = reinterpret_cast<char *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(buf_p));

  uint64_t bend_p = buf_p + count - 1;
  void *bend = Elkvm::vmi->get_region_manager().get_pager().get_host_p(bend_p);
  long result = 0;

  if(!Elkvm::vmi->get_region_manager().same_region(buf, bend)) {
    assert(Elkvm::vmi->get_region_manager().host_address_mapped(bend));
    char *host_begin_mark = NULL;
    char *host_end_mark = buf;
    uint64_t mark_p = buf_p;
    ssize_t current_count = count;
    do {
      host_begin_mark = reinterpret_cast<char *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(mark_p));
      std::shared_ptr<Elkvm::Region> region = Elkvm::vmi->get_region_manager().find_region(host_begin_mark);
      if(mark_p != buf_p) {
        assert(host_begin_mark == region->base_address());
      }

      host_end_mark = reinterpret_cast<char *>(region->last_valid_address());
      assert(host_end_mark > host_begin_mark);

      ssize_t newcount = host_end_mark - host_begin_mark;
      if(newcount > current_count) {
        newcount = current_count;
      }

      long in_result = vm->syscall_handlers->read((int)fd, host_begin_mark, newcount);
      if(in_result < 0) {
        return errno;
      }
      if(in_result < newcount) {
        return result + in_result;
      }
      if(vm->debug) {
        printf("\n============ LIBELKVM ===========\n");
        printf("READ from fd: %i with size 0x%lx of 0x%lx buf 0x%lx (%p)\n",
            (int)fd, newcount, count, buf_p, buf);
        printf("RESULT %li (0x%lx)\n", result,result);
        printf("=================================\n");
      }

      mark_p += in_result;
      current_count -= in_result;
      result += in_result;
    } while(!Elkvm::vmi->get_region_manager().same_region(host_begin_mark, bend));
    assert(current_count == 0);

  } else {
    result = vm->syscall_handlers->read((int)fd, buf, (size_t)count);
  }

  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("READ from fd: %i with size 0x%lx buf 0x%lx (%p)\n",
        (int)fd, count, buf_p, buf);
    printf("RESULT %li\n", result);
    printf("=================================\n");
  }

	return result;
}

long elkvm_do_write(struct kvm_vm *vm) {
  if(vm->syscall_handlers->write == NULL) {
    printf("WRITE handler not found\n");
    return -ENOSYS;
  }
  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

  uint64_t fd = 0x0;
  guestptr_t buf_p = 0x0;
  void *buf;
  uint64_t count = 0x0;

  elkvm_syscall3(vcpu, &fd, &buf_p, &count);

  assert(buf_p != 0x0);
  buf = Elkvm::vmi->get_region_manager().get_pager().get_host_p(buf_p);

  std::shared_ptr<Elkvm::Region> r = Elkvm::vmi->get_region_manager().find_region(buf);
  assert(r != nullptr);

  char *current_buf = reinterpret_cast<char *>(buf);
  size_t remaining_count = count;
  ssize_t total = 0;
  while(!r->contains_address(current_buf + remaining_count - 1)) {
    long result = vm->syscall_handlers->write(static_cast<int>(fd),
        current_buf, r->space_after_address(current_buf));
    if(result < 0) {
      return -errno;
    }
    total += result;

    if(vm->debug) {
      printf("\n============ LIBELKVM ===========\n");
      printf("SPLIT WRITE to fd: %i with size 0x%lx buf 0x%lx (%p)\n",
          (int)fd, count, buf_p, buf);
      printf("\tcurrent buf: %p remaining bytes: 0x%lx\n",
          current_buf, remaining_count);
      printf("RESULT %li\n", result);
      printf("=================================\n");
    }
    current_buf += result;
    remaining_count -= result;
    r = Elkvm::vmi->get_region_manager().find_region(current_buf);
  }
  assert(r->contains_address(reinterpret_cast<char *>(buf) + count - 1));

  long result = vm->syscall_handlers->write(static_cast<int>(fd),
      current_buf, remaining_count);
  if(result < 0) {
    return -errno;
  }
  total += result;

  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("WRITE to fd: %i with size 0x%lx buf 0x%lx (%p)\n",
        (int)fd, count, buf_p, buf);
    printf("RESULT %li\n", result);
    printf("=================================\n");
  }

  return total;
}

long elkvm_do_open(struct kvm_vm *vm) {
	if(vm->syscall_handlers->open == NULL) {
		printf("OPEN handler not found\n");
		return -ENOSYS;
	}
  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

	uint64_t pathname_p = 0x0;
	char *pathname = NULL;
	uint64_t flags = 0x0;
	uint64_t mode = 0x0;

	elkvm_syscall3(vcpu, &pathname_p, &flags, &mode);

  assert(pathname_p != 0x0);
	pathname = reinterpret_cast<char *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(pathname_p));

	long result = vm->syscall_handlers->open(pathname, (int)flags, (mode_t)mode);

  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("OPEN file %s with flags %i and mode %x\n", pathname,
			(int)flags, (mode_t)mode);
    printf("RESULT: %li\n", result);
    printf("=================================\n");
  }

	return result;
}

long elkvm_do_close(struct kvm_vm *vm) {
	if(vm->syscall_handlers->close == NULL) {
		printf("CLOSE handler not found\n");
		return -ENOSYS;
	}
  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

	uint64_t fd = 0;
	elkvm_syscall1(vcpu, &fd);

  if(vm->debug) {
    printf("CLOSE file with fd: %li\n", fd);
  }
	long result = vm->syscall_handlers->close((int)fd);

  if(vm->debug) {
    printf("RESULT: %li\n", result);
  }

	return result;
}

long elkvm_do_stat(struct kvm_vm *vm) {
  if(vm->syscall_handlers->stat == NULL) {
    printf("STAT handler not found\n");
    return -ENOSYS;
  }
  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

  uint64_t path_p = 0;
  uint64_t buf_p = 0;
  char *path = NULL;
  struct stat *buf;
  elkvm_syscall2(vcpu, &path_p, &buf_p);

  assert(path_p != 0x0);
  path = reinterpret_cast<char *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(path_p));
  assert(buf_p != 0x0);
  buf  = reinterpret_cast<struct stat *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(buf_p));

  long result = vm->syscall_handlers->stat(path, buf);
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("STAT file %s with buf at: 0x%lx (%p)\n",
        path, buf_p, buf);
    printf("RESULT: %li\n", result);
    printf("=================================\n");
  }

  return result;
}

long elkvm_do_fstat(struct kvm_vm *vm) {
  if(vm->syscall_handlers->fstat == NULL) {
    printf("FSTAT handler not found\n");
    return -ENOSYS;
  }
  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

  uint64_t fd = 0;
  uint64_t buf_p = 0;
  struct stat *buf = NULL;
  elkvm_syscall2(vcpu, &fd, &buf_p);

  assert(buf_p != 0x0);
	buf = reinterpret_cast<struct stat *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(buf_p));

  if(vm->debug) {
    printf("FSTAT file with fd %li buf at 0x%lx (%p)\n", fd, buf_p, buf);
  }
  long result = vm->syscall_handlers->fstat(fd, buf);

  if(vm->debug) {
    printf("RESULT: %li\n", result);
  }

  return result;
}

long elkvm_do_lstat(struct kvm_vm *vm) {
  if(vm->syscall_handlers->lstat == NULL) {
    printf("LSTAT handler not found\n");
    return -ENOSYS;
  }
  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

  uint64_t path_p = 0;
  uint64_t buf_p = 0;
  char *path = NULL;
  struct stat *buf;
  elkvm_syscall2(vcpu, &path_p, &buf_p);

  assert(path_p != 0x0);
  path = reinterpret_cast<char *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(path_p));
  assert(buf_p != 0x0);
  buf  = reinterpret_cast<struct stat *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(buf_p));

  long result = vm->syscall_handlers->lstat(path, buf);
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("LSTAT file %s with buf at: 0x%lx (%p)\n",
        path, buf_p, buf);
    printf("RESULT: %li\n", result);
    printf("=================================\n");
  }

  return result;
}

long elkvm_do_poll(struct kvm_vm *vm __attribute__((unused))) {
	return -ENOSYS;
}

long elkvm_do_lseek(struct kvm_vm *vm) {
  if(vm->syscall_handlers->lseek == NULL) {
    printf("LSEEK handler not found\n");
    return -ENOSYS;
  }

  uint64_t fd;
  uint64_t off;
  uint64_t whence;
  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

  elkvm_syscall3(vcpu, &fd, &off, &whence);

  long result = vm->syscall_handlers->lseek(fd, off, whence);
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("LSEEK fd %lu offset %lu whence %lu\n",
        fd, off, whence);
    printf("RESULT: %li\n", result);
    printf("=================================\n");

  }
  return result;


}

long elkvm_do_mmap(struct kvm_vm *vm) {
  /* obtain a region_mapping and fill this with a proposal
   * on how to do the mapping */
  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);
  guestptr_t addr = 0x0;
  uint64_t length = 0x0;
  uint64_t prot   = 0x0;
  uint64_t flags  = 0x0;
  uint64_t fd     = 0;
  uint64_t off    = 0;

  elkvm_syscall6(vcpu, &addr, &length, &prot, &flags, &fd, &off);

  /* create a mapping object with the data from the user, this will
   * also allocate the memory for this mapping */
  Elkvm::Mapping &mapping =
    Elkvm::vmi->get_region_manager().get_mapping(addr, length, prot, flags, fd, off);


  /* if a handler is specified, call the monitor for corrections etc. */
  long result = 0;
  if(vm->syscall_handlers->mmap_before != NULL) {
    struct region_mapping *cm = mapping.c_mapping();
    result = vm->syscall_handlers->mmap_before(cm);
    /* write changes back to mapping obj */
    mapping.sync_back(cm);
    free(cm);
  }

  /* now do the standard actions not handled by the monitor
   * i.e. copy data for file-based mappings, split existing mappings for
   * MAP_FIXED if necessary etc. */

  if(!mapping.anonymous()) {
    mapping.fill();
  }

  /* call the monitor again, so it can do what has been left */
  if(vm->syscall_handlers->mmap_after != NULL) {
    result = vm->syscall_handlers->mmap_after(mapping.c_mapping());
  }

  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("MMAP addr 0x%lx length %lu (0x%lx) prot %lu flags %lu",
        addr, length, length, prot, flags);
    if(!(flags & MAP_ANONYMOUS)) {
      printf(" fd %lu offset %li", fd, off);
    }
    if(flags & MAP_FIXED) {
      printf(" MAP_FIXED");
    }
    printf("\n");

    printf("RESULT: %li\n", result);
    printf("=================================\n");
  }
  if(result < 0) {
    return -errno;
  }

  return mapping.guest_address();
}

long elkvm_do_mprotect(struct kvm_vm *vm) {
  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

  guestptr_t addr = 0;
  uint64_t len = 0;
  uint64_t prot = 0;
  elkvm_syscall3(vcpu, &addr, &len, &prot);

  assert(page_aligned(addr) && "mprotect address must be page aligned");
  if(!Elkvm::vmi->get_region_manager().address_mapped(addr)) {
    Elkvm::vmi->get_region_manager().dump_regions();
    std::cout << "mprotect with invalid address: 0x" << std::hex
      << addr << std::endl;
    return -EINVAL;
  }

  Elkvm::Mapping &mapping = Elkvm::vmi->get_region_manager().find_mapping(addr);
  int err = 0;
  if(mapping.get_length() != len) {
    /* we need to split this mapping */
    mapping.slice(addr, len);
    Elkvm::Mapping new_mapping(addr, len, prot, mapping.get_flags(),
        mapping.get_fd(), mapping.get_offset());
    new_mapping.map_self();
    Elkvm::vmi->get_region_manager().add_mapping(new_mapping);
  } else {
    /* only modify this mapping */
    err = mapping.mprotect(prot);
  }

  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("MPROTECT reguested with address: 0x%lx len: 0x%lx prot: %i\n",
        addr, len, (int)prot);
    print(std::cout, mapping);
    printf("RESULT: %i\n", err);
    printf("=================================\n");
  }

	return err;
}

long elkvm_do_munmap(struct kvm_vm *vm) {
  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

  guestptr_t addr_p = 0;
  void *addr = NULL;
  uint64_t length = 0;
  elkvm_syscall2(vcpu, &addr_p, &length);

  if(addr_p != 0x0) {
    addr = Elkvm::vmi->get_region_manager().get_pager().get_host_p(addr_p);
  }

  auto chunk = Elkvm::vmi->get_region_manager().get_pager().find_chunk_for_host_p(addr);
  assert(chunk != nullptr);

  Elkvm::Mapping &mapping = Elkvm::vmi->get_region_manager().find_mapping(addr);
  mapping.unmap(addr_p, pages_from_size(length));

  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("MUNMAP reguested with address: 0x%lx (%p) length: 0x%lx\n",
        addr_p, addr, length);
    if(!mapping.all_unmapped()) {
      print(std::cout, mapping);
    }
    printf("=================================\n");
  }

  return 0;

}

long elkvm_do_brk(struct kvm_vm *vm) {
  guestptr_t user_brk_req = 0;
  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);
  elkvm_syscall1(vcpu, &user_brk_req);

  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("BRK reguested with address: 0x%lx current brk address: 0x%lx\n",
        user_brk_req, Elkvm::vmi->get_heap_manager().get_brk());
  }

  /* if the requested brk address is 0 just return the current brk address */
  if(user_brk_req == 0) {
    if(vm->debug) {
      printf("=================================\n");
    }
    return Elkvm::vmi->get_heap_manager().get_brk();
  }

  int err = Elkvm::vmi->get_heap_manager().brk(user_brk_req);
  if(vm->debug) {
    printf("BRK done: err: %i (%s) newbrk: 0x%lx\n",
        err, strerror(err), Elkvm::vmi->get_heap_manager().get_brk());
    printf("=================================\n");
  }
  if(err) {
    return err;
  }
  return Elkvm::vmi->get_heap_manager().get_brk();
}

long elkvm_do_sigaction(struct kvm_vm *vm) {
  if(vm->syscall_handlers->sigaction == NULL) {
    printf("SIGACTION handler not found\n");
    return -ENOSYS;
  }

  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);
  uint64_t signum;
  uint64_t act_p;
  uint64_t oldact_p;

  elkvm_syscall3(vcpu, &signum, &act_p, &oldact_p);

  struct sigaction *act = NULL;
  struct sigaction *oldact = NULL;
  if(act_p != 0x0) {
    act = reinterpret_cast<struct sigaction *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(act_p));
  }
  if(oldact_p != 0x0) {
    oldact = reinterpret_cast<struct sigaction *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(oldact_p));
  }

  int err = 0;
  if(vm->syscall_handlers->sigaction((int)signum, act, oldact)) {
    err = elkvm_signal_register(vm, (int)signum, act, oldact);
  }

  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf(" SIGACTION with signum: %i act: 0x%lx (%p) oldact: 0x%lx (%p)\n",
        (int)signum, act_p, act, oldact_p, oldact);
    if(err != 0) {
      printf("ERROR: %i\n", errno);
    }
    printf("=================================\n");

  }

  return err;
}

long elkvm_do_sigprocmask(struct kvm_vm *vm) {
  if(vm->syscall_handlers->sigprocmask == NULL) {
    printf("SIGPROCMASK handler not found\n");
    return -ENOSYS;
  }

  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

  uint64_t how;
  uint64_t set_p;
  uint64_t oldset_p;

  elkvm_syscall3(vcpu, &how, &set_p, &oldset_p);

  sigset_t *set = NULL;
  sigset_t *oldset = NULL;
  if(set_p != 0x0) {
    set = reinterpret_cast<sigset_t *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(set_p));
  }
  if(oldset_p != 0x0) {
    oldset = reinterpret_cast<sigset_t *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(oldset_p));
  }

  long result = vm->syscall_handlers->sigprocmask(how, set, oldset);
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("RT SIGPROCMASK with how: %i (%p) set: 0x%lx (%p) oldset: 0x%lx (%p)\n",
        (int)how, &how, set_p, set, oldset_p, oldset);
    printf("RESULT: %li\n", result);
    if(result < 0) {
      printf("ERROR No: %i Msg: %s\n", errno, strerror(errno));
    }
    printf("=================================\n");

  }
  return result;
}

long elkvm_do_sigreturn(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_ioctl(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_pread64(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_pwrite64(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

void elkvm_get_host_iov(struct kvm_vm *vm __attribute__((unused)),
    uint64_t iov_p, uint64_t iovcnt, struct iovec *host_iov) {
  struct iovec *guest_iov = NULL;
  assert(iov_p != 0x0);
  guest_iov = reinterpret_cast<struct iovec *>
    (Elkvm::vmi->get_region_manager().get_pager().get_host_p(iov_p));

  for(unsigned i = 0; i < iovcnt; i++) {
    assert(guest_iov[i].iov_base != NULL);
    host_iov[i].iov_base = Elkvm::vmi->get_region_manager().get_pager().get_host_p(
        reinterpret_cast<guestptr_t>(guest_iov[i].iov_base));
    host_iov[i].iov_len  = guest_iov[i].iov_len;
  }

}

long elkvm_do_readv(struct kvm_vm *vm) {
  if(vm->syscall_handlers->readv == NULL) {
    printf("READV handler not found\n");
    return -ENOSYS;
  }
  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

  uint64_t fd = 0;
  uint64_t iov_p = 0;
  uint64_t iovcnt = 0;

  elkvm_syscall3(vcpu, &fd, &iov_p, &iovcnt);

  struct iovec host_iov[iovcnt];
  elkvm_get_host_iov(vm, iov_p, iovcnt, host_iov);

  long result = vm->syscall_handlers->readv(fd, host_iov, iovcnt);
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("READV with fd: %i (%p) iov: 0x%lx iovcnt: %i\n",
        (int)fd, &fd, iov_p, (int)iovcnt);
    printf("RESULT: %li\n", result);
    if(result < 0) {
      printf("ERROR No: %i Msg: %s\n", errno, strerror(errno));
    }
    printf("=================================\n");
  }
  return result;
}

long elkvm_do_writev(struct kvm_vm *vm) {
  if(vm->syscall_handlers->writev == NULL) {
    printf("WRITEV handler not found\n");
    return -ENOSYS;
  }
  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

  uint64_t fd = 0;
  uint64_t iov_p = 0;
  uint64_t iovcnt = 0;

  elkvm_syscall3(vcpu, &fd, &iov_p, &iovcnt);

  struct iovec host_iov[iovcnt];
  elkvm_get_host_iov(vm, iov_p, iovcnt, host_iov);

  long result = vm->syscall_handlers->writev(fd, host_iov, iovcnt);
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("WRITEV with fd: %i iov: 0x%lx iovcnt: %i\n",
        (int)fd, iov_p, (int)iovcnt);
    printf("RESULT: %li\n", result);
    printf("=================================\n");
  }
  return result;
}

long elkvm_do_access(struct kvm_vm *vm) {
	if(vm->syscall_handlers->access == NULL) {
    printf("ACCESS handler not found\n");
		return -ENOSYS;
	}
  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

  uint64_t path_p;
  uint64_t mode;

  elkvm_syscall2(vcpu, &path_p, &mode);

  assert(path_p != 0x0);
  char *pathname = reinterpret_cast<char *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(path_p));
  if(pathname == NULL) {
    return -EFAULT;
  }

  long result = vm->syscall_handlers->access(pathname, mode);
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("ACCESS with pathname: %s (0x%lx) mode: %i\n",
      pathname, path_p, (int)mode);
    printf("RESULT: %li\n", result);
    printf("=================================\n");
  }

  if(result) {
    return -errno;
  }

  return 0;
}

long elkvm_do_pipe(struct kvm_vm *vm) {
  if(vm->syscall_handlers->pipe == NULL) {
    printf("PIPE handler not found\n");
    return -ENOSYS;
  }

  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

  uint64_t pipefd_p = 0x0;
  int *pipefd = NULL;

  elkvm_syscall1(vcpu, &pipefd_p);

  pipefd = reinterpret_cast<int *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(pipefd_p));
  assert(pipefd != NULL);

  long result = vm->syscall_handlers->pipe(pipefd);
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("PIPE with pipefds at: %p (0x%lx)\n",
        pipefd, pipefd_p);
    printf("RESULT: %li\n", result);
    printf("=================================\n");
  }
  if(result) {
    return -errno;
  }

  return 0;
}

long elkvm_do_select(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_sched_yield(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_mremap(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_msync(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_mincore(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_madvise(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_shmget(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_shmat(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_shmctl(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_dup(struct kvm_vm *vm) {
	if(vm->syscall_handlers->dup == NULL) {
    printf("DUP handler not found\n");
		return -ENOSYS;
	}
  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

  uint64_t oldfd;

  elkvm_syscall1(vcpu, &oldfd);

  if(vm->debug) {
    printf("CALLING DUP handler with oldfd %i\n",
      (int)oldfd);
  }

  long result = vm->syscall_handlers->dup(oldfd);
  if(vm->debug) {
    printf("DUP result: %li\n", result);
  }

  return -errno;
}

long elkvm_do_dup2(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_pause(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_nanosleep(struct kvm_vm *vm) {
  if(vm->syscall_handlers->nanosleep == NULL) {
    printf("NANOSLEEP handler not found\n");
    return -ENOSYS;
  }

  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

  uint64_t req_p;
  uint64_t rem_p;
  elkvm_syscall2(vcpu, &req_p, &rem_p);

  struct timespec *req = NULL;
  struct timespec *rem = NULL;

  if(req_p != 0x0) {
    req = reinterpret_cast<struct timespec *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(req_p));
  }
  if(rem_p != 0x0) {
    rem = reinterpret_cast<struct timespec *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(rem_p));
  }

  long result = vm->syscall_handlers->nanosleep(req, rem);
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("NANOSLEEP\n");
    printf("RESULT: %li\n", result);
    printf("=================================\n");
  }

  return result;
}

long elkvm_do_getitimer(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_alarm(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_setitimer(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_getpid(struct kvm_vm *vm) {
  if(vm->syscall_handlers->getpid == NULL) {
    return -ENOSYS;
  }

  long pid = vm->syscall_handlers->getpid();
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("GETPID\n");
    printf("RESULT: %li\n", pid);
    printf("=================================\n");
  }

  return pid;
}

long elkvm_do_sendfile(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_socket(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_connect(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_accept(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_sendto(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_recvfrom(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_sendmsg(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_recvmsg(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_shutdown(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_bind(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_listen(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_getsockname(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_getpeername(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_socketpair(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_setsockopt(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_getsockopt(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_clone(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_fork(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_vfork(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_execve(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_exit(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_wait4(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_kill(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_uname(struct kvm_vm *vm) {
	if(vm->syscall_handlers->uname == NULL) {
		return -ENOSYS;
	}
  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

	struct utsname *buf = NULL;
	uint64_t bufp = 0;
	elkvm_syscall1(vcpu, &bufp);

  assert(bufp != 0x0);
	buf = (struct utsname *)Elkvm::vmi->get_region_manager().get_pager().get_host_p(bufp);
  assert(buf != NULL && "host buffer address cannot be NULL in uname");

	long result = vm->syscall_handlers->uname(buf);
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("UNAME buf at: 0x%lx (%p)\n", bufp, buf);
    printf("syname: %s nodename: %s release: %s version: %s machine: %s\n",
			buf->sysname, buf->nodename, buf->release, buf->version, buf->machine);
    printf("RESULT: %li\n", result);
    printf("=================================\n");
  }
	return result;
}

long elkvm_do_semget(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_semop(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_semctl(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_shmdt(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_msgget(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_msgsnd(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_msgrcv(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_msgctl(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_fcntl(struct kvm_vm *vm) {
  if(vm->syscall_handlers->fcntl == NULL) {
    printf("FCNTL handler not found\n");
    return -ENOSYS;
  }

  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

  uint64_t fd = 0;
  uint64_t cmd = 0;
  /*
   * depending on the value of cmd arg is either an int or a pointer
   * to a struct flock or a pointer to a struct f_owner_ex
   */
  uint64_t arg_p = 0;

  elkvm_syscall3(vcpu, &fd, &cmd, &arg_p);

  long result = 0;
  switch(cmd) {
    case F_GETOWN_EX:
    case F_SETOWN_EX:
    case F_GETLK:
    case F_SETLK:
    case F_SETLKW: {
      /* NULL statement */;
      void *arg = Elkvm::vmi->get_region_manager().get_pager().get_host_p(arg_p);
      result = vm->syscall_handlers->fcntl(fd, cmd, arg);
      break;
                   }
    default:
      result = vm->syscall_handlers->fcntl(fd, cmd, arg_p);
      break;
  }

  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("FCNTL with fd: %lu cmd: %lu arg_p: 0x%lx\n",
        fd, cmd, arg_p);
    printf("RESULT: %li\n", result);
    if(result < 0) {
      printf("ERROR No: %i Msg: %s\n", errno, strerror(errno));
    }
    printf("=================================\n");
  }

  return result;
}

long elkvm_do_flock(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_fsync(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_fdatasync(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_truncate(struct kvm_vm *vm) {
  if(vm->syscall_handlers->truncate == NULL) {
    printf("TRUNCATE handler not found\n");
    return -ENOSYS;
  }

  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

  uint64_t path_p = 0;
  uint64_t length;
  char *path = NULL;

  elkvm_syscall2(vcpu, &path_p, &length);

  path = reinterpret_cast<char *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(path_p));
  long result = vm->syscall_handlers->truncate(path, length);
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("TRUNCATE with path at: %p (%s) length %lu\n",
        path, path, length);
    printf("RESULT: %li\n", result);
    if(result < 0) {
      printf("ERROR No: %i Msg: %s\n", errno, strerror(errno));
    }
    printf("=================================\n");
  }
  return result;
}

long elkvm_do_ftruncate(struct kvm_vm *vm) {
  if(vm->syscall_handlers->ftruncate == NULL) {
    printf("FTRUNCATE handler not found\n");
    return -ENOSYS;
  }

  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

  uint64_t fd = 0;
  uint64_t length;

  elkvm_syscall2(vcpu, &fd, &length);

  long result = vm->syscall_handlers->ftruncate(fd, length);
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("FTRUNCATE with fd: %lu length %lu\n",
        fd, length);
    printf("RESULT: %li\n", result);
    if(result < 0) {
      printf("ERROR No: %i Msg: %s\n", errno, strerror(errno));
    }
    printf("=================================\n");
  }
  return result;
}

long elkvm_do_getdents(struct kvm_vm *vm __attribute__((unused))) {
  if(vm->syscall_handlers->getdents == NULL) {
    std::cout << "GETDENTS handler not found\n";
    return -ENOSYS;
  }

  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

  uint64_t fd = 0;
  guestptr_t dirp_p = 0x0;
  uint64_t count = 0;

  elkvm_syscall3(vcpu, &fd, &dirp_p, &count);

  struct linux_dirent *dirp = NULL;
  if(dirp_p != 0x0) {
    dirp = reinterpret_cast<struct linux_dirent *>(
        Elkvm::vmi->get_region_manager().get_pager().get_host_p(dirp_p));
  }

  int res = vm->syscall_handlers->getdents(fd, dirp, count);
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("GETDENTS with fd: %u dirp: 0x%lx (%p) count %u\n",
        (unsigned)fd, dirp_p, dirp, (unsigned)count);
    printf("RESULT: %i\n", res);
    if(res < 0) {
      printf("ERROR No: %i Msg: %s\n", errno, strerror(errno));
    }
    printf("=================================\n");
  }
  if(res < 0) {
    return -errno;
  }
  return res;
}

long elkvm_do_getcwd(struct kvm_vm *vm) {
  if(vm->syscall_handlers->getcwd == NULL) {
    printf("GETCWD handler not found\n");
    return -ENOSYS;
  }

  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

  uint64_t buf_p = 0;
  uint64_t size = 0;
  char *buf = NULL;

  elkvm_syscall2(vcpu, &buf_p, &size);

  buf = reinterpret_cast<char *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(buf_p));

  char *result = vm->syscall_handlers->getcwd(buf, size);
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("GETCWD with buf at: 0x%lx (%p) size %lu\n",
        buf_p, buf, size);
    printf("RESULT: %p (%s)\n", result, result);
    if(result == NULL) {
      printf("ERROR No: %i Msg: %s\n", errno, strerror(errno));
    }
    printf("=================================\n");
  }
  if(result == NULL) {
    return errno;
  } else {
    return 0;
  }
}

long elkvm_do_chdir(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_fchdir(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_rename(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_mkdir(struct kvm_vm *vm) {
  if(vm->syscall_handlers->mkdir == NULL) {
    printf("MKDIR handler not found\n");
    return -ENOSYS;
  }

  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

  uint64_t pathname_p = 0;
  uint64_t mode = 0;
  char *pathname = NULL;

  elkvm_syscall2(vcpu, &pathname_p, &mode);

  assert(pathname_p != 0x0);
  pathname = reinterpret_cast<char *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(pathname_p));
  long result = vm->syscall_handlers->mkdir(pathname, mode);
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("MKDIR with pathname at: %p (%s) mode %lu\n",
        pathname, pathname, mode);
    printf("RESULT: %li\n", result);
    if(result < 0) {
      printf("ERROR No: %i Msg: %s\n", errno, strerror(errno));
    }
    printf("=================================\n");
  }
  return result;

}

long elkvm_do_rmdir(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_creat(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_link(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_unlink(struct kvm_vm *vm) {
  if(vm->syscall_handlers->unlink == NULL) {
    printf("UNLINK handler not found\n");
    return -ENOSYS;
  }
  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

  uint64_t pathname_p = 0;
  char *pathname = NULL;

  elkvm_syscall1(vcpu, &pathname_p);

  assert(pathname_p != 0x0);
  pathname = reinterpret_cast<char *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(pathname_p));
  long result = vm->syscall_handlers->unlink(pathname);
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("UNLINK with pathname at: %p (%s)\n",
        pathname, pathname);
    printf("RESULT: %li\n", result);
    if(result < 0) {
      printf("ERROR No: %i Msg: %s\n", errno, strerror(errno));
    }
    printf("=================================\n");
  }
  return result;
}

long elkvm_do_symlink(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_readlink(struct kvm_vm *vm) {
  if(vm->syscall_handlers->readlink == NULL) {
    printf("READLINK handler not found\n");
    return -ENOSYS;
  }

  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

  uint64_t path_p = 0;
  uint64_t buf_p = 0;
  uint64_t bufsiz = 0;
  char *path = NULL;
  char *buf = NULL;

  elkvm_syscall3(vcpu, &path_p, &buf_p, &bufsiz);

  path = reinterpret_cast<char *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(path_p));
  buf  = reinterpret_cast<char *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(buf_p));
  long result = vm->syscall_handlers->readlink(path, buf, bufsiz);
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("READLINK with path at: %p (%s) buf at: %p bufsize: %lu\n",
        path, path, buf, bufsiz);
    printf("RESULT: %li\n", result);
    if(result < 0) {
      printf("ERROR No: %i Msg: %s\n", errno, strerror(errno));
    }
    printf("=================================\n");
  }
  return result;
}

long elkvm_do_chmod(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_fchmod(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_chown(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_fchown(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_lchown(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_umask(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_gettimeofday(struct kvm_vm *vm) {
  if(vm->syscall_handlers->gettimeofday == NULL) {
    return -ENOSYS;
  }

  uint64_t tv_p = 0;
  uint64_t tz_p = 0;
  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);
  elkvm_syscall2(vcpu, &tv_p, &tz_p);

  struct timeval *tv = NULL;
  struct timezone *tz = NULL;

  if(tv_p != 0x0) {
    tv = reinterpret_cast<struct timeval *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(tv_p));
  }
  if(tz_p != 0x0) {
    tz = reinterpret_cast<struct timezone *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(tz_p));
  }

  long result = vm->syscall_handlers->gettimeofday(tv, tz);
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("GETTIMEOFDAY with timeval: %lx (%p) timezone: %lx (%p)\n",
        tv_p, tv, tz_p, tz);
    printf("RESULT: %li\n", result);
    if(result == 0) {
      if(tv != NULL) {
        printf("timeval: tv_sec: %lu tv_usec: %lu\n", tv->tv_sec, tv->tv_usec);
      }
      if(tz != NULL) {
        printf("timezone: tz_minuteswest: %i tz_dsttime %i\n",
          tz->tz_minuteswest, tz->tz_dsttime);
      }
    } else {
      printf("ERROR No: %i Msg: %s\n", errno, strerror(errno));
    }
    printf("=================================\n");
  }

  return result;
}

long elkvm_do_getrlimit(struct kvm_vm *vm) {
  uint64_t resource = 0x0;
  uint64_t rlim_p = 0x0;
  struct rlimit *rlim = NULL;

  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);
  elkvm_syscall2(vcpu, &resource, &rlim_p);

  assert(rlim_p != 0x0);
  rlim = reinterpret_cast<struct rlimit *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(rlim_p));

  memcpy(rlim, &vm->rlimits[resource], sizeof(struct rlimit));
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("GETRLIMIT with resource: %li rlim: 0x%lx (%p)\n",
        resource, rlim_p, rlim);
    printf("=================================\n");
  }

  return 0;
}

long elkvm_do_getrusage(struct kvm_vm *vm) {
  if(vm->syscall_handlers->getrusage == NULL) {
    printf("GETRUSAGE handler not found\n");
    return -ENOSYS;
  }

  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

  uint64_t who = 0;
  uint64_t usage_p = 0x0;
  struct rusage *usage = NULL;

  elkvm_syscall2(vcpu, &who, &usage_p);

  assert(usage_p != 0x0);
  assert(who == RUSAGE_SELF);

  usage = reinterpret_cast<struct rusage *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(usage_p));

  long result = vm->syscall_handlers->getrusage(who, usage);
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("RUSAGE with who: %li usage: %p (0x%lx)\n",
        who, usage, usage_p);
    printf("=================================\n");
  }
  return result;
}

long elkvm_do_sysinfo(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_times(struct kvm_vm *vm) {
  if(vm->syscall_handlers->times == NULL) {
    printf("TIMES handler not found\n");
    return -ENOSYS;
  }
  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

  uint64_t buf_p = 0x0;
  struct tms *buf = NULL;

  elkvm_syscall1(vcpu, &buf_p);
  assert(buf_p != 0x0);

  buf = reinterpret_cast<struct tms *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(buf_p));
  assert(buf != NULL);

  long result = vm->syscall_handlers->times(buf);
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("TIMES with buf: 0x%lx (%p)\n",
        buf_p, buf);
    printf("Result: %li\n", result);
    if(result >= 0) {
      printf("utime: %li stime: %li cutime: %li cstime: %li\n",
          buf->tms_utime, buf->tms_stime, buf->tms_cutime, buf->tms_cstime);
    }
    printf("=================================\n");
  }

  if(result == -1) {
    return -errno;
  } else {
    return result;
  }
}

long elkvm_do_ptrace(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_getuid(struct kvm_vm *vm) {
	if(vm->syscall_handlers->getuid == NULL) {
		printf("GETUID handler not found\n");
		return -ENOSYS;
	}

	long result = vm->syscall_handlers->getuid();
  if(vm->debug) {
    printf("GETUID RESULT: %li\n", result);
  }

	return result;
}

long elkvm_do_syslog(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_getgid(struct kvm_vm *vm) {
	if(vm->syscall_handlers->getgid == NULL) {
		printf("GETGID handler not found\n");
		return -ENOSYS;
	}

	long result = vm->syscall_handlers->getgid();
  if(vm->debug) {
    printf("GETGID RESULT: %li\n", result);
  }

	return result;
}

long elkvm_do_setuid(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_setgid(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_geteuid(struct kvm_vm *vm) {
	if(vm->syscall_handlers->geteuid == NULL) {
		printf("GETEUID handler not found\n");
		return -ENOSYS;
	}

	long result = vm->syscall_handlers->geteuid();
  if(vm->debug) {
    printf("GETEUID RESULT: %li\n", result);
  }

	return result;
}

long elkvm_do_getegid(struct kvm_vm *vm) {
	if(vm->syscall_handlers->getegid == NULL) {
		printf("GETEGID handler not found\n");
		return -ENOSYS;
	}

	long result = vm->syscall_handlers->getegid();
  if(vm->debug) {
    printf("GETEGID RESULT: %li\n", result);
  }

	return result;
}

long elkvm_do_setpgid(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_getppid(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_getpgrp(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_setsid(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_setreuid(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_setregid(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_getgroups(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_setgroups(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_setresuid(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_getresuid(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_setresgid(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_getresgid(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_getpgid(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_setfsuid(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_setfsgid(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_getsid(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_capget(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_capset(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_rt_sigpending(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_rt_sigtimedwait(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_rt_sigqueueinfo(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_rt_sigsuspend(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_sigaltstack(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_utime(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_mknod(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_uselib(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_personality(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_ustat(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_statfs(struct kvm_vm *vm __attribute__((unused))) {
  if(vm->syscall_handlers->statfs == NULL) {
    std::cout << "STATFS handler not found\n";
    return -ENOSYS;
  }

  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);
  guestptr_t path_p = 0x0;
  guestptr_t buf_p = 0x0;

  elkvm_syscall2(vcpu, &path_p, &buf_p);

  char *path = NULL;
  struct statfs *buf = NULL;
  if(path_p != 0x0) {
    path = reinterpret_cast<char *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(path_p));
  }
  if(buf_p != 0x0) {
    buf = reinterpret_cast<struct statfs *>(
        Elkvm::vmi->get_region_manager().get_pager().get_host_p(buf_p));
  }

  int res = vm->syscall_handlers->statfs(path, buf);
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("STATFS path 0x%lx (%p) buf 0x%lx (%p)",
        path_p, path, buf_p, buf);
    printf("RESULT: %i\n", res);
    printf("=================================\n");
  }

  if(res == 0) {
    return 0;
  }
  return -errno;
}

long elkvm_do_fstatfs(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_sysfs(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_getpriority(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_setpriority(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_sched_setparam(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_sched_getparam(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_sched_setscheduler(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_sched_getscheduler(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_sched_get_priority_max(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_sched_get_priority_min(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_sched_rr_get_interval(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_mlock(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_munlock(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_mlockall(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_munlockall(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_vhangup(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_modify_ldt(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_pivot_root(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_sysctl(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_prctl(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_arch_prctl(struct kvm_vm *vm) {
  uint64_t code = 0;
  uint64_t user_addr = 0;
  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

  int err = kvm_vcpu_get_sregs(vcpu);
  if(err) {
    return err;
  }

  elkvm_syscall2(vcpu, &code, &user_addr);
  assert(user_addr != 0x0);
  uint64_t *host_addr = reinterpret_cast<uint64_t *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(user_addr));
  if(host_addr == NULL) {
    return -EFAULT;
  }

  if(vm->debug) {
    printf("ARCH PRCTL with code %i user_addr 0x%lx\n", (int)code, user_addr);
  }
  switch(code) {
    case ARCH_SET_FS:
      vcpu->sregs.fs.base = user_addr;
      break;
    case ARCH_GET_FS:
      *host_addr = vcpu->sregs.fs.base;
      break;
    case ARCH_SET_GS:
      vcpu->sregs.gs.base = user_addr;
      break;
    case ARCH_GET_GS:
      *host_addr = vcpu->sregs.gs.base;
      break;
    default:
      return -EINVAL;
  }

  err = kvm_vcpu_set_sregs(vcpu);
  if(err) {
    return err;
  }

  return 0;
}

long elkvm_do_adjtimex(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_setrlimit(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_chroot(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_sync(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_acct(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_settimeofday(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_mount(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_umount2(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_swapon(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_swapoff(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_reboot(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_sethostname(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_setdomainname(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_iopl(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_ioperm(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_create_module(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_init_module(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_delete_module(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_get_kernel_syms(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_query_module(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_quotactl(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_nfsservctl(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_getpmsg(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_putpmsg(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_afs_syscall(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_tuxcall(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_security(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_gettid(struct kvm_vm *vm) {
  if(vm->syscall_handlers->gettid == NULL) {
    printf("GETTID handler not found\n");
    return -ENOSYS;
  }

  long result = vm->syscall_handlers->gettid();
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("GETTID\n");
    printf("RESULT: %li\n", result);
    printf("=================================\n");
  }
  return result;
}

long elkvm_do_readahead(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_setxattr(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_lsetxattr(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_fsetxattr(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_getxattr(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_lgetxattr(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_fgetxattr(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_listxattr(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_llistxattr(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_flistxattr(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_removexattr(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_lremovexattr(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_fremovexattr(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_tkill(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_time(struct kvm_vm *vm) {
  if(vm->syscall_handlers->time == NULL) {
    printf("TIME handler not found\n");
    return -ENOSYS;
  }

  uint64_t time_p = 0;
  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);
  elkvm_syscall1(vcpu, &time_p);

  time_t *time = NULL;
  if(time_p != 0x0) {
    time = reinterpret_cast<time_t *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(time_p));
  }

  long result = vm->syscall_handlers->time(time);
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("TIME with arg %lx (%p)\n", time_p, time);
    printf("RESULT: %li\n", result);
    printf("=================================\n");
  }

  return result;
}

long elkvm_do_futex(struct kvm_vm *vm) {
  if(vm->syscall_handlers->futex == NULL) {
    printf("FUTEX handler not found\n");
    return -ENOSYS;
  }

  uint64_t uaddr_p = 0x0;
  uint64_t op = 0;
  uint64_t val = 0;
  uint64_t timeout_p = 0x0;
  uint64_t uaddr2_p = 0x0;
  uint64_t val3 = 0;
  int *uaddr = NULL;
  const struct timespec *timeout = NULL;
  int *uaddr2 = NULL;

  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);
  elkvm_syscall6(vcpu, &uaddr_p, &op, &val, &timeout_p, &uaddr2_p, &val3);

  if(uaddr_p != 0x0) {
    uaddr = reinterpret_cast<int *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(uaddr_p));
  }
  if(timeout_p != 0x0) {
    timeout = reinterpret_cast<const struct timespec *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(timeout_p));
  }
  if(uaddr2_p != 0x0) {
    uaddr2 = reinterpret_cast<int *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(uaddr2_p));
  }

  printf("FUTEX with uaddr %p (0x%lx) op %lu val %lu timeout %p (0x%lx)"
      " uaddr2 %p (0x%lx) val3 %lu\n",
      uaddr, uaddr_p, op, val, timeout, timeout_p, uaddr2, uaddr2_p, val3);
  long result = vm->syscall_handlers->futex(uaddr, op, val, timeout, uaddr2, val3);
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("FUTEX with uaddr %p (0x%lx) op %lu val %lu timeout %p (0x%lx)"
        " uaddr2 %p (0x%lx) val3 %lu\n",
        uaddr, uaddr_p, op, val, timeout, timeout_p, uaddr2, uaddr2_p, val3);
    printf("RESULT: %li\n", result);
    printf("=================================\n");
  }

  if(result) {
    return -errno;
  }
  return result;

}

long elkvm_do_sched_setaffinity(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_sched_getaffinity(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_set_thread_area(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_io_setup(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_io_destroy(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_getevents(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_submit(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_cancel(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_get_thread_area(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_lookup_dcookie(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_epoll_create(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_epoll_ctl_old(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_epoll_wait_old(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_remap_file_pages(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_getdents64(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_set_tid_address(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_restart_syscall(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_semtimedop(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_fadive64(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_timer_create(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_timer_settime(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_timer_gettime(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_timer_getoverrun(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_timer_delete(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_clock_settime(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_clock_gettime(struct kvm_vm *vm) {
  if(vm->syscall_handlers->clock_gettime == NULL) {
    printf("CLOCK GETTIME handler not found\n");
    return -ENOSYS;
  }

  uint64_t clk_id = 0x0;
  uint64_t tp_p = 0x0;
  struct timespec *tp = NULL;

  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);
  assert(vcpu != NULL);

  elkvm_syscall2(vcpu, &clk_id, &tp_p);
  assert(tp_p != 0x0);

  tp = reinterpret_cast<struct timespec *>(Elkvm::vmi->get_region_manager().get_pager().get_host_p(tp_p));
  assert(tp != NULL);

  long result = vm->syscall_handlers->clock_gettime(clk_id, tp);
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("CLOCK GETTIME with clk_id %li tp 0x%lx (%p)\n",
        clk_id, tp_p, tp);
    printf("RESULT: %li\n", result);
    printf("=================================\n");
  }
  return result;
}

long elkvm_do_clock_getres(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_clock_nanosleep(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_exit_group(struct kvm_vm *vm) {
  uint64_t status = 0;
  elkvm_syscall1(elkvm_vcpu_get(vm, 0), &status);

  vm->syscall_handlers->exit_group(status);
  /* should not be reached... */
  return -ENOSYS;
}

long elkvm_do_epoll_wait(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_epoll_ctl(struct kvm_vm *vm __attribute__((unused))) {
  return -ENOSYS;
}

long elkvm_do_tgkill(struct kvm_vm *vm) {
  if(vm->syscall_handlers->tgkill == NULL) {
    printf("TGKILL handler not found\n");
    return -ENOSYS;
  }

  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

  uint64_t tgid = 0x0;
  uint64_t tid = 0x0;
  uint64_t sig = 0x0;

  elkvm_syscall3(vcpu, &tgid, &tid, &sig);

  long result = vm->syscall_handlers->tgkill(tgid, tid, sig);
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("TGKILL with tgid %li tid %li sig %li\n", tgid, tid, sig);
    printf("RESULT: %li\n", result);
    printf("=================================\n");
  }
  return result;

}

long elkvm_do_openat(struct kvm_vm *vm __attribute__((unused))) {
  if(vm->syscall_handlers->openat == NULL) {
    printf("OPENAT handler not found\n");
    return -ENOSYS;
  }

  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

  uint64_t dirfd = 0;
  guestptr_t pathname_p = 0x0;
  uint64_t flags = 0;

  elkvm_syscall3(vcpu, &dirfd, &pathname_p, &flags);

  char *pathname = NULL;
  if(pathname_p != 0x0) {
    pathname = reinterpret_cast<char *>(
        Elkvm::vmi->get_region_manager().get_pager().get_host_p(pathname_p));
  }

  int res = vm->syscall_handlers->openat((int)dirfd, pathname, (int)flags);
  if(vm->debug) {
    printf("\n============ LIBELKVM ===========\n");
    printf("OPENAT with dirfd %i pathname 0x%lx (%p) flags %i\n",
        (int)dirfd, pathname_p, pathname, (int)flags);
    printf("RESULT: %i\n", res);
    printf("=================================\n");
  }

  if(res < 0) {
    return -errno;
  }

  return res;
}
