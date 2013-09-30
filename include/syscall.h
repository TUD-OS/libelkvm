#pragma once

#include "vcpu.h"
#include <asm/unistd_64.h>

#define ELKVM_HYPERCALL_SYSCALL   1
#define ELKVM_HYPERCALL_INTERRUPT 2
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
long elkvm_do_shmctl(struct kvm_vm *);
long elkvm_do_dup(struct kvm_vm *);
long elkvm_do_dup2(struct kvm_vm *);
long elkvm_do_pause(struct kvm_vm *);
long elkvm_do_nanosleep(struct kvm_vm *);
long elkvm_do_getitimer(struct kvm_vm *);
long elkvm_do_alarm(struct kvm_vm *);
long elkvm_do_setitimer(struct kvm_vm *);
long elkvm_do_getpid(struct kvm_vm *);
long elkvm_do_sendfile(struct kvm_vm *);
long elkvm_do_socket(struct kvm_vm *);
long elkvm_do_connect(struct kvm_vm *);
long elkvm_do_accept(struct kvm_vm *);
long elkvm_do_sendto(struct kvm_vm *);
long elkvm_do_recvfrom(struct kvm_vm *);
long elkvm_do_sendmsg(struct kvm_vm *);
long elkvm_do_recvmsg(struct kvm_vm *);
long elkvm_do_shutdown(struct kvm_vm *);
long elkvm_do_bind(struct kvm_vm *);
long elkvm_do_listen(struct kvm_vm *);
long elkvm_do_getsockname(struct kvm_vm *);
long elkvm_do_getpeername(struct kvm_vm *);
long elkvm_do_socketpair(struct kvm_vm *);
long elkvm_do_setsockopt(struct kvm_vm *);
long elkvm_do_getsockopt(struct kvm_vm *);
long elkvm_do_clone(struct kvm_vm *);
long elkvm_do_fork(struct kvm_vm *);
long elkvm_do_vfork(struct kvm_vm *);
long elkvm_do_execve(struct kvm_vm *);
long elkvm_do_exit(struct kvm_vm *);
long elkvm_do_wait4(struct kvm_vm *);
long elkvm_do_kill(struct kvm_vm *);
long elkvm_do_uname(struct kvm_vm *);
long elkvm_do_semget(struct kvm_vm *);
long elkvm_do_semop(struct kvm_vm *);
long elkvm_do_semctl(struct kvm_vm *);
long elkvm_do_shmdt(struct kvm_vm *);
long elkvm_do_msgget(struct kvm_vm *);
long elkvm_do_msgsnd(struct kvm_vm *);
long elkvm_do_msgrcv(struct kvm_vm *);
/* ... */
long elkvm_do_umask(struct kvm_vm *);
long elkvm_do_gettimeofday(struct kvm_vm *);
long elkvm_do_getrlimit(struct kvm_vm *);
long elkvm_do_getrusage(struct kvm_vm *);
long elkvm_do_sysinfo(struct kvm_vm *);
long elkvm_do_times(struct kvm_vm *);
long elkvm_do_ptrace(struct kvm_vm *);
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
long elkvm_do_time(struct kvm_vm *);
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
  [__NR_shmctl]      = { elkvm_do_shmctl, "SHMCTL" },
  [__NR_dup]         = { elkvm_do_dup, "DUP" },
  [__NR_dup2]        = { elkvm_do_dup2, "DUP2" },
  [__NR_pause]       = { elkvm_do_pause, "PAUSE" },
  [__NR_nanosleep]   = { elkvm_do_nanosleep, "NANOSLEEP" },
  [__NR_getitimer]   = { elkvm_do_getitimer, "GETITIMER" },
  [__NR_alarm]       = { elkvm_do_alarm, "ALARM" },
  [__NR_setitimer]   = { elkvm_do_setitimer, "SETITIMER" },
  [__NR_getpid]      = { elkvm_do_getpid, "GETPID" },
  [__NR_sendfile]    = { elkvm_do_sendfile, "SENDFILE" },
  [__NR_socket]      = { elkvm_do_socket, "SOCKET" },
  [__NR_connect]     = { elkvm_do_connect, "CONNECT" },
  [__NR_accept]      = { elkvm_do_accept, "ACCEPT" },
  [__NR_sendto]      = { elkvm_do_sendto, "SENDTO" },
  [__NR_recvfrom]    = { elkvm_do_recvfrom, "RECVFROM" },
  [__NR_sendmsg]     = { elkvm_do_sendmsg, "SENDMSG" },
  [__NR_recvmsg]     = { elkvm_do_recvmsg, "RECVMSG" },
  [__NR_shutdown]    = { elkvm_do_shutdown, "SHUTDOWN" },
  [__NR_bind]        = { elkvm_do_bind, "BIND" },
  [__NR_listen]      = { elkvm_do_listen, "LISTEN" },
  [__NR_getsockname] = { elkvm_do_getsockname, "GETSOCKNAME" },
  [__NR_getpeername] = { elkvm_do_getpeername, "GETPEERNAME" },
  [__NR_socketpair]  = { elkvm_do_socketpair, "SOCKETPAIR" },
  [__NR_setsockopt]  = { elkvm_do_setsockopt, "SETSOCKOPT" },
  [__NR_getsockopt]  = { elkvm_do_getsockopt, "GETSOCKOPT" },
  [__NR_clone]       = { elkvm_do_clone, "CLONE" },
  [__NR_fork]        = { elkvm_do_fork, "FORK" },
  [__NR_vfork]       = { elkvm_do_vfork, "VFORK" },
  [__NR_execve]      = { elkvm_do_execve, "EXECVE" },
  [__NR_exit]        = { elkvm_do_exit, "EXIT" },
  [__NR_wait4]       = { elkvm_do_wait4, "WAIT4" },
  [__NR_kill]        = { elkvm_do_kill, "KILL" },
  [__NR_uname]       = { elkvm_do_uname, "UNAME" },
  [__NR_semget]      = { elkvm_do_semget, "SEMGET" },
  [__NR_semop]       = { elkvm_do_semop, "SEMOP" },
  [__NR_semctl]      = { elkvm_do_semctl, "SEMCTL" },
  [__NR_shmdt]       = { elkvm_do_shmdt, "SHMDT" },
  [__NR_msgget]      = { elkvm_do_msgget, "MSGGET" },
  [__NR_msgsnd]      = { elkvm_do_msgsnd, "MSGSND" },
  [__NR_msgrcv]      = { elkvm_do_msgrcv, "MSGRCV" },
  /* ... */
  [__NR_umask]        = { elkvm_do_umask, "UMASK" },
  [__NR_gettimeofday] = { elkvm_do_gettimeofday, "GETTIMEOFDAY" },
  [__NR_getrlimit]    = { elkvm_do_getrlimit , "GETRLIMIT" },
  [__NR_getrusage]    = { elkvm_do_getrusage, "GETRUSAGE" },
  [__NR_sysinfo]      = { elkvm_do_sysinfo, "SYSINFO" },
  [__NR_times]        = { elkvm_do_times, "TIMES" },
  [__NR_ptrace]       = { elkvm_do_ptrace, "PTRACE" },
  [__NR_getuid]       = { elkvm_do_getuid, "GETUID" },
  [__NR_syslog]       = { elkvm_do_syslog, "SYSLOG" },
  [__NR_getgid]       = { elkvm_do_getgid, "GETGID" },
  [__NR_setuid]       = { elkvm_do_setuid, "SETUID" },
  [__NR_setgid]       = { elkvm_do_setgid, "SETGID" },
  [__NR_geteuid]      = { elkvm_do_geteuid, "GETEUID" },
  [__NR_getegid]      = { elkvm_do_getegid, "GETEGID" },
  /* ... */
  [__NR_arch_prctl] = { elkvm_do_arch_prctl, "ARCH PRCTL" },
  /* ... */
  [__NR_time]       = { elkvm_do_time, "TIME" },
  /* ... */
  [__NR_exit_group] = { elkvm_do_exit_group, "EXIT GROUP" },
};

