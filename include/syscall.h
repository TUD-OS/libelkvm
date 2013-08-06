#pragma once

#include "vcpu.h"
#include <asm/unistd_64.h>

/*
 * \brief check if the shutdown reason is a call from the guest
 * manager to the host
 * returns 1 if the vm is to keep running
 * returns 0 if the vm has had an error (#TF) and should stop running
 */
int elkvm_handle_vm_shutdown(struct kvm_vm *, struct kvm_vcpu *);

/*
 * \brief check what kind of syscall has been made by the guest
 * and call the appropriate handler func in the userspace binary
 */
int elkvm_handle_syscall(struct kvm_vm *);

long elkvm_do_read(struct kvm_vm *);
long elkvm_do_write(struct kvm_vm *);
long elkvm_do_open(struct kvm_vm *);
long elkvm_do_close(struct kvm_vm *);
long elkvm_do_stat(struct kvm_vm *);
long elkvm_do_fstat(struct kvm_vm *);
long elkvm_do_lstat(struct kvm_vm *);
long elkvm_do_poll(struct kvm_vm *);
long elkvm_do_lseek(struct kvm_vm *);
long elkvm_do_mmap(struct kvm_vm *);
/* ... */
long elkvm_do_uname(struct kvm_vm *);

static struct {
	long (*func)(struct kvm_vm *);
	const char *name;
} elkvm_syscalls[] = {
	[__NR_read]  = { elkvm_do_read, "READ" },
	[__NR_write] = { elkvm_do_write, "WRITE"},
	[__NR_open]  = { elkvm_do_open, "OPEN"},
	[__NR_close] = { elkvm_do_close, "CLOSE" },
	[__NR_stat]  = { elkvm_do_stat, "STAT" },
	[__NR_fstat] = { elkvm_do_fstat, "FSTAT" },
	[__NR_lstat] = { elkvm_do_lstat, "LSTAT" },
	[__NR_poll]  = { elkvm_do_poll, "POLL" },
	[__NR_lseek] = { elkvm_do_lseek, "LSEEK"},
	[__NR_mmap]  = { elkvm_do_mmap, "MMAP"},
	/* ... */
	[__NR_uname] = { elkvm_do_uname, "UNAME"},
};

#define NUM_SYSCALLS 313
