#pragma once

#include "vcpu.h"
#include <asm/unistd_64.h>

/*
 * \brief check what kind of syscall has been made by the guest
 * and call the appropriate handler func in the userspace binary
 */
int elkvm_handle_syscall(struct kvm_vm *, struct kvm_vcpu *);
int elkvm_handle_interrupt(struct kvm_vm *, struct kvm_vcpu *);
int elkvm_handle_hypercall(struct kvm_vm *, struct kvm_vcpu *);
int elkvm_syscall1(struct kvm_vm *, struct kvm_vcpu *, uint64_t *);
int elkvm_syscall2(struct kvm_vm *, struct kvm_vcpu *, uint64_t *, uint64_t *);
int elkvm_syscall3(struct kvm_vm *, struct kvm_vcpu *, uint64_t *, uint64_t *,
		uint64_t *);
int elkvm_syscall4(struct kvm_vm *, struct kvm_vcpu *, uint64_t *, uint64_t *,
		uint64_t *, uint64_t *);
int elkvm_syscall5(struct kvm_vm *, struct kvm_vcpu *, uint64_t *, uint64_t *,
		uint64_t *, uint64_t *, uint64_t *);
int elkvm_syscall6(struct kvm_vm *, struct kvm_vcpu *, uint64_t *, uint64_t *,
		uint64_t *, uint64_t *, uint64_t *, uint64_t *);


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
long elkvm_do_sigaction(struct kvm_vm *);
long elkvm_do_sigprocmask(struct kvm_vm *);
long elkvm_do_sigreturn(struct kvm_vm *);
long elkvm_do_ioctl(struct kvm_vm *);
long elkvm_do_pread64(struct kvm_vm *);
long elkvm_do_pwrite64(struct kvm_vm *);
long elkvm_do_readv(struct kvm_vm *);
long elkvm_do_writev(struct kvm_vm *);
long elkvm_do_access(struct kvm_vm *);
long elkvm_do_pipe(struct kvm_vm *);
long elkvm_do_select(struct kvm_vm *);
long elkvm_do_sched_yield(struct kvm_vm *);
long elkvm_do_mremap(struct kvm_vm *);
long elkvm_do_msync(struct kvm_vm *);
long elkvm_do_mincore(struct kvm_vm *);
long elkvm_do_madvise(struct kvm_vm *);
long elkvm_do_shmget(struct kvm_vm *);
long elkvm_do_shmat(struct kvm_vm *);
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
/* ... */
long elkvm_do_exit_group(struct kvm_vm *);

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
  [__NR_rt_sigaction] = { elkvm_do_sigaction, "SIGACTION" },
  [__NR_rt_sigprocmask] = { elkvm_do_sigprocmask, "SIGPROCMASK" },
  [__NR_rt_sigreturn]   = { elkvm_do_sigreturn, "SIGRETURN" },
  [__NR_ioctl]       = { elkvm_do_ioctl, "IOCTL" },
  [__NR_pread64]     = { elkvm_do_pread64, "PREAD64" },
  [__NR_readv]       = { elkvm_do_readv, "READV" },
  [__NR_writev]      = { elkvm_do_writev, "WRITEV" },
  [__NR_access]      = { elkvm_do_access, "ACCESS" },
  [__NR_pipe]        = { elkvm_do_pipe, "PIPE" },
  [__NR_select]      = { elkvm_do_select, "SELECT" },
  [__NR_sched_yield] = { elkvm_do_sched_yield, "SCHED YIELD" },
  [__NR_mremap]      = { elkvm_do_mremap, "MREMAP" },
  [__NR_msync]       = { elkvm_do_msync, "MSYNC" },
  [__NR_mincore]     = { elkvm_do_mincore, "MINCORE" },
  [__NR_madvise]     = { elkvm_do_madvise, "MADVISE" },
  [__NR_shmget]      = { elkvm_do_shmget, "SHMGET" },
  [__NR_shmat]       = { elkvm_do_shmat, "SHMAT" },
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
  /* ... */
  [__NR_exit_group] = { elkvm_do_exit_group, "EXIT GROUP" },
};

