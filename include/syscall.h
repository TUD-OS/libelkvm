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
int elkvm_handle_syscall(struct kvm_vm *, struct kvm_vcpu *);
int elkvm_syscall1(struct kvm_vm *, struct kvm_vcpu *, uint64_t *);
int elkvm_syscall2(struct kvm_vm *, struct kvm_vcpu *, uint64_t *, uint64_t *);
int elkvm_syscall3(struct kvm_vm *, struct kvm_vcpu *, uint64_t *, uint64_t *,
		uint64_t *);


#define NUM_SYSCALLS 313

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
long elkvm_do_mprotect(struct kvm_vm *);
long elkvm_do_munmap(struct kvm_vm *);
long elkvm_do_brk(struct kvm_vm *);
/* ... */
long elkvm_do_uname(struct kvm_vm *);
/* ... */
long elkvm_do_getuid(struct kvm_vm *);
long elkvm_do_syslog(struct kvm_vm *);
long elkvm_do_getgid(struct kvm_vm *);
long elkvm_do_setuid(struct kvm_vm *);
long elkvm_do_setgid(struct kvm_vm *);
long elkvm_do_geteuid(struct kvm_vm *);
long elkvm_do_getegid(struct kvm_vm *);
/* ... */
long elkvm_do_arch_prctl(struct kvm_vm *);

static struct {
	long (*func)(struct kvm_vm *);
	const char *name;
} elkvm_syscalls[NUM_SYSCALLS] = {
	[__NR_read]			= { elkvm_do_read, "READ" },
	[__NR_write] 		= { elkvm_do_write, "WRITE"},
	[__NR_open]  		= { elkvm_do_open, "OPEN"},
	[__NR_close] 		= { elkvm_do_close, "CLOSE" },
	[__NR_stat]  		= { elkvm_do_stat, "STAT" },
	[__NR_fstat] 		= { elkvm_do_fstat, "FSTAT" },
	[__NR_lstat] 		= { elkvm_do_lstat, "LSTAT" },
	[__NR_poll]  		= { elkvm_do_poll, "POLL" },
	[__NR_lseek] 		= { elkvm_do_lseek, "LSEEK" },
	[__NR_mmap]  		= { elkvm_do_mmap, "MMAP" },
	[__NR_mprotect] = { elkvm_do_mprotect, "MPROTECT" },
	[__NR_munmap]   = { elkvm_do_munmap, "MUNMAP" },
	[__NR_brk]      = { elkvm_do_brk, "BRK" },
	/* ... */
	[__NR_uname] = { elkvm_do_uname, "UNAME"},
  /* ... */
  [__NR_getuid]  = { elkvm_do_getuid, "GETUID" },
  [__NR_syslog]  = { elkvm_do_syslog, "SYSLOG" },
  [__NR_getgid]  = { elkvm_do_getgid, "GETGID" },
  [__NR_setuid]  = { elkvm_do_setuid, "SETUID" },
  [__NR_setgid]  = { elkvm_do_setgid, "SETGID" },
  [__NR_geteuid] = { elkvm_do_geteuid, "GETEUID" },
  [__NR_getegid] = { elkvm_do_getegid, "GETEGID" },
  /* ... */
  [__NR_arch_prctl] = { elkvm_do_arch_prctl, "ARCH PRCTL" },
};

