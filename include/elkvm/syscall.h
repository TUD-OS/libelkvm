#pragma once

#include "vcpu.h"
#include <asm/unistd_64.h>

#define ELKVM_HYPERCALL_SYSCALL   1
#define ELKVM_HYPERCALL_INTERRUPT 2

#define ELKVM_HYPERCALL_EXIT      0x42
#define NUM_SYSCALLS 313


#ifdef __cplusplus
extern "C" {
#endif

/*
 * \brief check what kind of syscall has been made by the guest
 * and call the appropriate handler func in the userspace binary
 */
int elkvm_handle_syscall(struct kvm_vm *, struct kvm_vcpu *);
int elkvm_handle_interrupt(struct kvm_vm *, struct kvm_vcpu *);
int elkvm_handle_hypercall(struct kvm_vm *, std::shared_ptr<struct kvm_vcpu>);
void elkvm_syscall1(struct kvm_vcpu *, uint64_t *);
void elkvm_syscall2(struct kvm_vcpu *, uint64_t *, uint64_t *);
void elkvm_syscall3(struct kvm_vcpu *, uint64_t *, uint64_t *,
 uint64_t *);
void elkvm_syscall4(struct kvm_vcpu *, uint64_t *, uint64_t *,
 uint64_t *, uint64_t *);
void elkvm_syscall5(struct kvm_vcpu *, uint64_t *, uint64_t *,
 uint64_t *, uint64_t *, uint64_t *);
void elkvm_syscall6(struct kvm_vcpu *, uint64_t *, uint64_t *,
		uint64_t *, uint64_t *, uint64_t *, uint64_t *);


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
long elkvm_do_msgctl(struct kvm_vm *);
long elkvm_do_fcntl(struct kvm_vm *);
long elkvm_do_flock(struct kvm_vm *);
long elkvm_do_fsync(struct kvm_vm *);
long elkvm_do_fdatasync(struct kvm_vm *);
long elkvm_do_truncate(struct kvm_vm *);
long elkvm_do_ftruncate(struct kvm_vm *);
long elkvm_do_getdents(struct kvm_vm *);
long elkvm_do_getcwd(struct kvm_vm *);
long elkvm_do_chdir(struct kvm_vm *);
long elkvm_do_fchdir(struct kvm_vm *);
long elkvm_do_rename(struct kvm_vm *);
long elkvm_do_mkdir(struct kvm_vm *);
long elkvm_do_rmdir(struct kvm_vm *);
long elkvm_do_creat(struct kvm_vm *);
long elkvm_do_link(struct kvm_vm *);
long elkvm_do_unlink(struct kvm_vm *);
long elkvm_do_symlink(struct kvm_vm *);
long elkvm_do_readlink(struct kvm_vm *);
long elkvm_do_chmod(struct kvm_vm *);
long elkvm_do_fchmod(struct kvm_vm *);
long elkvm_do_chown(struct kvm_vm *);
long elkvm_do_fchown(struct kvm_vm *);
long elkvm_do_lchown(struct kvm_vm *);
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
long elkvm_do_setpgid(struct kvm_vm *);
long elkvm_do_getppid(struct kvm_vm *);
long elkvm_do_getpgrp(struct kvm_vm *);
long elkvm_do_setsid(struct kvm_vm *);
long elkvm_do_setreuid(struct kvm_vm *);
long elkvm_do_setregid(struct kvm_vm *);
long elkvm_do_getgroups(struct kvm_vm *);
long elkvm_do_setgroups(struct kvm_vm *);
long elkvm_do_setresuid(struct kvm_vm *);
long elkvm_do_getresuid(struct kvm_vm *);
long elkvm_do_setresgid(struct kvm_vm *);
long elkvm_do_getresgid(struct kvm_vm *);
long elkvm_do_getpgid(struct kvm_vm *);
long elkvm_do_setfsuid(struct kvm_vm *);
long elkvm_do_setfsgid(struct kvm_vm *);
long elkvm_do_getsid(struct kvm_vm *);
long elkvm_do_capget(struct kvm_vm *);
long elkvm_do_capset(struct kvm_vm *);
long elkvm_do_rt_sigpending(struct kvm_vm *);
long elkvm_do_rt_sigtimedwait(struct kvm_vm *);
long elkvm_do_rt_sigqueueinfo(struct kvm_vm *);
long elkvm_do_rt_sigsuspend(struct kvm_vm *);
long elkvm_do_sigaltstack(struct kvm_vm *);
long elkvm_do_utime(struct kvm_vm *);
long elkvm_do_mknod(struct kvm_vm *);
long elkvm_do_uselib(struct kvm_vm *);
long elkvm_do_personality(struct kvm_vm *);
long elkvm_do_ustat(struct kvm_vm *);
long elkvm_do_statfs(struct kvm_vm *);
long elkvm_do_fstatfs(struct kvm_vm *);
long elkvm_do_sysfs(struct kvm_vm *);
long elkvm_do_getpriority(struct kvm_vm *);
long elkvm_do_setpriority(struct kvm_vm *);
long elkvm_do_sched_setparam(struct kvm_vm *);
long elkvm_do_sched_getparam(struct kvm_vm *);
long elkvm_do_sched_setscheduler(struct kvm_vm *);
long elkvm_do_sched_getscheduler(struct kvm_vm *);
long elkvm_do_sched_get_priority_max(struct kvm_vm *);
long elkvm_do_sched_get_priority_min(struct kvm_vm *);
long elkvm_do_sched_rr_get_interval(struct kvm_vm *);
long elkvm_do_mlock(struct kvm_vm *);
long elkvm_do_munlock(struct kvm_vm *);
long elkvm_do_mlockall(struct kvm_vm *);
long elkvm_do_munlockall(struct kvm_vm *);
long elkvm_do_vhangup(struct kvm_vm *);
long elkvm_do_modify_ldt(struct kvm_vm *);
long elkvm_do_pivot_root(struct kvm_vm *);
long elkvm_do_sysctl(struct kvm_vm *);
long elkvm_do_prctl(struct kvm_vm *);
long elkvm_do_arch_prctl(struct kvm_vm *);
long elkvm_do_adjtimex(struct kvm_vm *vm);
long elkvm_do_setrlimit(struct kvm_vm *vm);
long elkvm_do_chroot(struct kvm_vm *vm);
long elkvm_do_sync(struct kvm_vm *vm);
long elkvm_do_acct(struct kvm_vm *vm);
long elkvm_do_settimeofday(struct kvm_vm *vm);
long elkvm_do_mount(struct kvm_vm *vm);
long elkvm_do_umount2(struct kvm_vm *vm);
long elkvm_do_swapon(struct kvm_vm *vm);
long elkvm_do_swapoff(struct kvm_vm *vm);
long elkvm_do_reboot(struct kvm_vm *vm);
long elkvm_do_sethostname(struct kvm_vm *vm);
long elkvm_do_setdomainname(struct kvm_vm *vm);
long elkvm_do_iopl(struct kvm_vm *vm);
long elkvm_do_ioperm(struct kvm_vm *vm);
long elkvm_do_create_module(struct kvm_vm *vm);
long elkvm_do_init_module(struct kvm_vm *vm);
long elkvm_do_delete_module(struct kvm_vm *vm);
long elkvm_do_get_kernel_syms(struct kvm_vm *vm);
long elkvm_do_query_module(struct kvm_vm *vm);
long elkvm_do_quotactl(struct kvm_vm *vm);
long elkvm_do_nfsservctl(struct kvm_vm *vm);
long elkvm_do_getpmsg(struct kvm_vm *vm);
long elkvm_do_putpmsg(struct kvm_vm *vm);
long elkvm_do_afs_syscall(struct kvm_vm *vm);
long elkvm_do_tuxcall(struct kvm_vm *vm);
long elkvm_do_security(struct kvm_vm *vm);
long elkvm_do_gettid(struct kvm_vm *vm);
long elkvm_do_readahead(struct kvm_vm *vm);
long elkvm_do_setxattr(struct kvm_vm *vm);
long elkvm_do_lsetxattr(struct kvm_vm *vm);
long elkvm_do_fsetxattr(struct kvm_vm *vm);
long elkvm_do_getxattr(struct kvm_vm *vm);
long elkvm_do_lgetxattr(struct kvm_vm *vm);
long elkvm_do_fgetxattr(struct kvm_vm *vm);
long elkvm_do_listxattr(struct kvm_vm *vm);
long elkvm_do_llistxattr(struct kvm_vm *vm);
long elkvm_do_flistxattr(struct kvm_vm *vm);
long elkvm_do_removexattr(struct kvm_vm *vm);
long elkvm_do_lremovexattr(struct kvm_vm *vm);
long elkvm_do_fremovexattr(struct kvm_vm *vm);
long elkvm_do_tkill(struct kvm_vm *vm);
long elkvm_do_time(struct kvm_vm *);
long elkvm_do_futex(struct kvm_vm *vm);
long elkvm_do_sched_setaffinity(struct kvm_vm *vm);
long elkvm_do_sched_getaffinity(struct kvm_vm *vm);
long elkvm_do_set_thread_area(struct kvm_vm *vm);
long elkvm_do_io_setup(struct kvm_vm *vm);
long elkvm_do_io_destroy(struct kvm_vm *vm);
long elkvm_do_getevents(struct kvm_vm *vm);
long elkvm_do_submit(struct kvm_vm *vm);
long elkvm_do_cancel(struct kvm_vm *vm);
long elkvm_do_get_thread_area(struct kvm_vm *vm);
long elkvm_do_lookup_dcookie(struct kvm_vm *vm);
long elkvm_do_epoll_create(struct kvm_vm *vm);
long elkvm_do_epoll_ctl_old(struct kvm_vm *vm);
long elkvm_do_epoll_wait_old(struct kvm_vm *vm);
long elkvm_do_remap_file_pages(struct kvm_vm *vm);
long elkvm_do_getdents64(struct kvm_vm *vm);
long elkvm_do_set_tid_address(struct kvm_vm *vm);
long elkvm_do_restart_syscall(struct kvm_vm *vm);
long elkvm_do_semtimedop(struct kvm_vm *vm);
long elkvm_do_fadive64(struct kvm_vm *vm);
long elkvm_do_timer_create(struct kvm_vm *vm);
long elkvm_do_timer_settime(struct kvm_vm *vm);
long elkvm_do_timer_gettime(struct kvm_vm *vm);
long elkvm_do_timer_getoverrun(struct kvm_vm *vm);
long elkvm_do_timer_delete(struct kvm_vm *vm);
long elkvm_do_clock_settime(struct kvm_vm *);
long elkvm_do_clock_gettime(struct kvm_vm *);
long elkvm_do_clock_getres(struct kvm_vm *);
long elkvm_do_clock_nanosleep(struct kvm_vm *);
long elkvm_do_exit_group(struct kvm_vm *);
long elkvm_do_epoll_wait(struct kvm_vm *);
long elkvm_do_epoll_ctl(struct kvm_vm *);
long elkvm_do_tgkill(struct kvm_vm *);
long elkvm_do_utimes(struct kvm_vm *);
long elkvm_do_vserver(struct kvm_vm *);
long elkvm_do_mbind(struct kvm_vm *);
long elkvm_do_mpolicy(struct kvm_vm *);
long elkvm_do_get_mempolicy(struct kvm_vm *);
long elkvm_do_mq_open(struct kvm_vm *);
long elkvm_do_mq_unlink(struct kvm_vm *);
long elkvm_do_mq_timedsend(struct kvm_vm *);
long elkvm_do_mq_timedreceive(struct kvm_vm *);
long elkvm_do_mq_notify(struct kvm_vm *);
long elkvm_do_getsetattr(struct kvm_vm *);
long elkvm_do_kexec_load(struct kvm_vm *);
long elkvm_do_waitid(struct kvm_vm *);
long elkvm_do_add_key(struct kvm_vm *);
long elkvm_do_request_key(struct kvm_vm *);
long elkvm_do_keyctl(struct kvm_vm *);
long elkvm_do_ioprio_set(struct kvm_vm *);
long elkvm_do_ioprio_get(struct kvm_vm *);
long elkvm_do_inotify_init(struct kvm_vm *);
long elkvm_do_inotify_add_watch(struct kvm_vm *);
long elkvm_do_inotify_rm_watch(struct kvm_vm *);
long elkvm_do_migrate_pages(struct kvm_vm *);
long elkvm_do_openat(struct kvm_vm *);

static struct {
	long (*func)(struct kvm_vm *);
	const char *name;
} elkvm_syscalls[NUM_SYSCALLS] = {
	[__NR_read]			      = { elkvm_do_read, "READ" },
	[__NR_write] 		      = { elkvm_do_write, "WRITE"},
	[__NR_open]  		      = { elkvm_do_open, "OPEN"},
	[__NR_close] 		      = { elkvm_do_close, "CLOSE" },
	[__NR_stat]  		      = { elkvm_do_stat, "STAT" },
	[__NR_fstat] 		      = { elkvm_do_fstat, "FSTAT" },
	[__NR_lstat] 		      = { elkvm_do_lstat, "LSTAT" },
	[__NR_poll]  		      = { elkvm_do_poll, "POLL" },
	[__NR_lseek] 		      = { elkvm_do_lseek, "LSEEK" },
	[__NR_mmap]  		      = { elkvm_do_mmap, "MMAP" },
	[__NR_mprotect]       = { elkvm_do_mprotect, "MPROTECT" },
	[__NR_munmap]         = { elkvm_do_munmap, "MUNMAP" },
	[__NR_brk]            = { elkvm_do_brk, "BRK" },
  [__NR_rt_sigaction]   = { elkvm_do_sigaction, "SIGACTION" },
  [__NR_rt_sigprocmask] = { elkvm_do_sigprocmask, "SIGPROCMASK" },
  [__NR_rt_sigreturn]   = { elkvm_do_sigreturn, "SIGRETURN" },
  [__NR_ioctl]          = { elkvm_do_ioctl, "IOCTL" },
  [__NR_pread64]        = { elkvm_do_pread64, "PREAD64" },
  [__NR_pwrite64]       = { elkvm_do_pwrite64, "PWRITE64" },
  [__NR_readv]          = { elkvm_do_readv, "READV" },
  [__NR_writev]         = { elkvm_do_writev, "WRITEV" },
  [__NR_access]         = { elkvm_do_access, "ACCESS" },
  [__NR_pipe]           = { elkvm_do_pipe, "PIPE" },
  [__NR_select]         = { elkvm_do_select, "SELECT" },
  [__NR_sched_yield]    = { elkvm_do_sched_yield, "SCHED YIELD" },
  [__NR_mremap]         = { elkvm_do_mremap, "MREMAP" },
  [__NR_msync]          = { elkvm_do_msync, "MSYNC" },
  [__NR_mincore]        = { elkvm_do_mincore, "MINCORE" },
  [__NR_madvise]        = { elkvm_do_madvise, "MADVISE" },
  [__NR_shmget]         = { elkvm_do_shmget, "SHMGET" },
  [__NR_shmat]          = { elkvm_do_shmat, "SHMAT" },
  [__NR_shmctl]         = { elkvm_do_shmctl, "SHMCTL" },
  [__NR_dup]            = { elkvm_do_dup, "DUP" },
  [__NR_dup2]           = { elkvm_do_dup2, "DUP2" },
  [__NR_pause]          = { elkvm_do_pause, "PAUSE" },
  [__NR_nanosleep]      = { elkvm_do_nanosleep, "NANOSLEEP" },
  [__NR_getitimer]      = { elkvm_do_getitimer, "GETITIMER" },
  [__NR_alarm]          = { elkvm_do_alarm, "ALARM" },
  [__NR_setitimer]      = { elkvm_do_setitimer, "SETITIMER" },
  [__NR_getpid]         = { elkvm_do_getpid, "GETPID" },
  [__NR_sendfile]       = { elkvm_do_sendfile, "SENDFILE" },
  [__NR_socket]         = { elkvm_do_socket, "SOCKET" },
  [__NR_connect]        = { elkvm_do_connect, "CONNECT" },
  [__NR_accept]         = { elkvm_do_accept, "ACCEPT" },
  [__NR_sendto]         = { elkvm_do_sendto, "SENDTO" },
  [__NR_recvfrom]       = { elkvm_do_recvfrom, "RECVFROM" },
  [__NR_sendmsg]        = { elkvm_do_sendmsg, "SENDMSG" },
  [__NR_recvmsg]        = { elkvm_do_recvmsg, "RECVMSG" },
  [__NR_shutdown]       = { elkvm_do_shutdown, "SHUTDOWN" },
  [__NR_bind]           = { elkvm_do_bind, "BIND" },
  [__NR_listen]         = { elkvm_do_listen, "LISTEN" },
  [__NR_getsockname]    = { elkvm_do_getsockname, "GETSOCKNAME" },
  [__NR_getpeername]    = { elkvm_do_getpeername, "GETPEERNAME" },
  [__NR_socketpair]     = { elkvm_do_socketpair, "SOCKETPAIR" },
  [__NR_setsockopt]     = { elkvm_do_setsockopt, "SETSOCKOPT" },
  [__NR_getsockopt]     = { elkvm_do_getsockopt, "GETSOCKOPT" },
  [__NR_clone]          = { elkvm_do_clone, "CLONE" },
  [__NR_fork]           = { elkvm_do_fork, "FORK" },
  [__NR_vfork]          = { elkvm_do_vfork, "VFORK" },
  [__NR_execve]         = { elkvm_do_execve, "EXECVE" },
  [__NR_exit]           = { elkvm_do_exit, "EXIT" },
  [__NR_wait4]          = { elkvm_do_wait4, "WAIT4" },
  [__NR_kill]           = { elkvm_do_kill, "KILL" },
  [__NR_uname]          = { elkvm_do_uname, "UNAME" },
  [__NR_semget]         = { elkvm_do_semget, "SEMGET" },
  [__NR_semop]          = { elkvm_do_semop, "SEMOP" },
  [__NR_semctl]         = { elkvm_do_semctl, "SEMCTL" },
  [__NR_shmdt]          = { elkvm_do_shmdt, "SHMDT" },
  [__NR_msgget]         = { elkvm_do_msgget, "MSGGET" },
  [__NR_msgsnd]         = { elkvm_do_msgsnd, "MSGSND" },
  [__NR_msgrcv]         = { elkvm_do_msgrcv, "MSGRCV" },
  [__NR_msgctl]         = { elkvm_do_msgctl, "MSGCTL" },
  [__NR_fcntl]          = { elkvm_do_fcntl, "FCNTL" },
  [__NR_flock]          = { elkvm_do_flock, "FLOCK" },
  [__NR_fsync]          = { elkvm_do_fsync, "FSYNC" },
  [__NR_fdatasync]      = { elkvm_do_fdatasync, "FDATASYNC" },
  [__NR_truncate]       = { elkvm_do_truncate, "TRUNCATE" },
  [__NR_ftruncate]      = { elkvm_do_ftruncate, "FTRUNCATE" },
  [__NR_getdents]       = { elkvm_do_getdents, "GETDENTS" },
  [__NR_getcwd]         = { elkvm_do_getcwd, "GETCWD" },
  [__NR_chdir]          = { elkvm_do_chdir, "CHDIR" },
  [__NR_fchdir]         = { elkvm_do_fchdir, "FCHDIR" },
  [__NR_rename]         = { elkvm_do_rename, "RENAME" },
  [__NR_mkdir]          = { elkvm_do_mkdir, "MKDIR" },
  [__NR_rmdir]          = { elkvm_do_rmdir, "RMDIR" },
  [__NR_creat]          = { elkvm_do_creat, "CREAT" },
  [__NR_link]           = { elkvm_do_link, "LINK" },
  [__NR_unlink]         = { elkvm_do_unlink, "UNLINK" },
  [__NR_symlink]        = { elkvm_do_symlink, "SYMLINK" },
  [__NR_readlink]       = { elkvm_do_readlink, "READLINK" },
  [__NR_chmod]          = { elkvm_do_chmod, "CHMOD" },
  [__NR_fchmod]         = { elkvm_do_fchmod, "FCHMOD" },
  [__NR_chown]          = { elkvm_do_chown, "CHOWN" },
  [__NR_fchown]         = { elkvm_do_fchown, "FCHOWN" },
  [__NR_lchown]         = { elkvm_do_lchown, "LCHOWN" },
  [__NR_umask]          = { elkvm_do_umask, "UMASK" },
  [__NR_gettimeofday]   = { elkvm_do_gettimeofday, "GETTIMEOFDAY" },
  [__NR_getrlimit]      = { elkvm_do_getrlimit , "GETRLIMIT" },
  [__NR_getrusage]      = { elkvm_do_getrusage, "GETRUSAGE" },
  [__NR_sysinfo]        = { elkvm_do_sysinfo, "SYSINFO" },
  [__NR_times]          = { elkvm_do_times, "TIMES" },
  [__NR_ptrace]         = { elkvm_do_ptrace, "PTRACE" },
  [__NR_getuid]         = { elkvm_do_getuid, "GETUID" },
  [__NR_syslog]         = { elkvm_do_syslog, "SYSLOG" },
  [__NR_getgid]         = { elkvm_do_getgid, "GETGID" },
  [__NR_setuid]         = { elkvm_do_setuid, "SETUID" },
  [__NR_setgid]         = { elkvm_do_setgid, "SETGID" },
  [__NR_geteuid]        = { elkvm_do_geteuid, "GETEUID" },
  [__NR_getegid]        = { elkvm_do_getegid, "GETEGID" },
  [__NR_setpgid]        = { elkvm_do_setpgid, "GETPGID" },
  [__NR_getppid]        = { elkvm_do_getppid, "GETPPID" },
  [__NR_getpgrp]        = { elkvm_do_getpgrp, "GETPGRP" },
  [__NR_setsid]         = { elkvm_do_setsid, "SETSID" },
  [__NR_setreuid]       = { elkvm_do_setreuid, "SETREUID" },
  [__NR_setregid]       = { elkvm_do_setregid, "SETREGID" },
  [__NR_getgroups]      = { elkvm_do_getgroups, "GETGROUPS" },
  [__NR_setgroups]      = { elkvm_do_setgroups, "SETGROUPS" },
  [__NR_setresuid]      = { elkvm_do_setresuid, "SETRESUID" },
  [__NR_getresuid]      = { elkvm_do_getresuid, "GETRESUID" },
  [__NR_setresgid]      = { elkvm_do_setresgid, "SETRESGID" },
  [__NR_getresgid]      = { elkvm_do_getresgid, "GETRESGID" },
  [__NR_getpgid]        = { elkvm_do_getpgid, "GETPGID" },
  [__NR_setfsuid]       = { elkvm_do_setfsuid, "SETFSUID" },
  [__NR_setfsgid]       = { elkvm_do_setfsgid, "SETFSGID" },
  [__NR_getsid]         = { elkvm_do_getsid, "GETSID" },
  [__NR_capget]         = { elkvm_do_capget, "CAPGET" },
  [__NR_capset]         = { elkvm_do_capset, "CAPSET" },
  [__NR_rt_sigpending]  = { elkvm_do_rt_sigpending, "RT SIGPENDING" },
  [__NR_rt_sigtimedwait] = { elkvm_do_rt_sigtimedwait, "RT SIGTIMEDWAIT" },
  [__NR_rt_sigqueueinfo] = { elkvm_do_rt_sigqueueinfo, "RT SIGQUEUEINFO" },
  [__NR_rt_sigsuspend]   = { elkvm_do_rt_sigsuspend, "RT SIGSUSPEND" },
  [__NR_sigaltstack]     = { elkvm_do_sigaltstack, "SIGALTSTACK" },
  [__NR_utime]           = { elkvm_do_utime, "UTIME" },
  [__NR_mknod]           = { elkvm_do_mknod, "MKNOD" },
  [__NR_uselib]          = { elkvm_do_uselib, "USELIB" },
  [__NR_personality]     = { elkvm_do_personality, "PERSONALITY" },
  [__NR_ustat]           = { elkvm_do_ustat, "USTAT" },
  [__NR_statfs]          = { elkvm_do_statfs, "STATFS" },
  [__NR_fstatfs]         = { elkvm_do_fstatfs, "FSTATFS" },
  [__NR_sysfs]           = { elkvm_do_sysfs, "SYSFS" },
  [__NR_getpriority]     = { elkvm_do_getpriority, "GETPRIORITY" },
  [__NR_setpriority]     = { elkvm_do_setpriority, "SETPRIORITY" },
  [__NR_sched_setparam]  = { elkvm_do_sched_setparam, "SCHED SETPARAM" },
  [__NR_sched_getparam]  = { elkvm_do_sched_getparam, "SCHED GETPARAM" },
  [__NR_sched_setscheduler] = { elkvm_do_sched_setscheduler, "SCHED SETSCHEDULER" },
  [__NR_sched_getscheduler] = { elkvm_do_sched_getscheduler, "SCHED GETSCHEDULER" },
  [__NR_sched_get_priority_max] = { elkvm_do_sched_get_priority_max, "SCHED GET PRIORITY MAX" },
  [__NR_sched_get_priority_min] = { elkvm_do_sched_get_priority_min, "SCHED GET PRIORITY MIN" },
  [__NR_sched_rr_get_interval]  = { elkvm_do_sched_rr_get_interval, "SCHED RR GET INTERVAL" },
  [__NR_mlock]                  = { elkvm_do_mlock, "MLOCK" },
  [__NR_munlock]                = { elkvm_do_munlock, "MUNLOCK" },
  [__NR_mlockall]               = { elkvm_do_mlockall, "MLOCKALL" },
  [__NR_munlockall]             = { elkvm_do_munlockall, "MUNLOCKALL" },
  [__NR_vhangup]                = { elkvm_do_vhangup, "VHANGUP" },
  [__NR_modify_ldt]             = { elkvm_do_modify_ldt, "MODIFY LDT" },
  [__NR_pivot_root]             = { elkvm_do_pivot_root, "PIVOT ROOT" },
  [__NR__sysctl]                = { elkvm_do_sysctl, " SYSCTL" },
  [__NR_prctl]                  = { elkvm_do_prctl, "PRCTL" },
  [__NR_arch_prctl]             = { elkvm_do_arch_prctl, "ARCH PRCTL" },
  [__NR_adjtimex]               = { elkvm_do_adjtimex, "ADJTIMEX" },
  [__NR_setrlimit]              = { elkvm_do_setrlimit, "SETRLIMIT" },
  [__NR_chroot]                 = { elkvm_do_chroot, "CHROOT" },
  [__NR_sync]                   = { elkvm_do_sync, "SYNC" },
  [__NR_acct]                   = { elkvm_do_acct, "ACCT" },
  [__NR_settimeofday]           = { elkvm_do_settimeofday, "SETTIMEOFDAY" },
  [__NR_mount]                  = { elkvm_do_mount, "MOUNT" },
  [__NR_umount2]                = { elkvm_do_umount2, "UMOUNT2" },
  [__NR_swapon]                 = { elkvm_do_swapon, "SWAPON" },
  [__NR_swapoff]                = { elkvm_do_swapoff, "SWAPOFF" },
  [__NR_reboot]                 = { elkvm_do_reboot, "REBOOT" },
  [__NR_sethostname]            = { elkvm_do_sethostname, "SETHOSTNAME" },
  [__NR_setdomainname]          = { elkvm_do_setdomainname, "SETDOMAINNAME" },
  [__NR_iopl]                   = { elkvm_do_iopl, "IOPL" },
  [__NR_ioperm]                 = { elkvm_do_ioperm, "IOPERM" },
  [__NR_create_module]          = { elkvm_do_create_module, "CREATE MODULE" },
  [__NR_init_module]            = { elkvm_do_init_module, "INIT MODULE" },
  [__NR_delete_module]          = { elkvm_do_delete_module, "DELETE MODULE" },
  [__NR_get_kernel_syms]        = { elkvm_do_get_kernel_syms, "GET KERNEL SYMS" },
  [__NR_query_module]           = { elkvm_do_query_module, "QUERY MODULE" },
  [__NR_quotactl]               = { elkvm_do_quotactl, "QUOTACTL" },
  [__NR_nfsservctl]             = { elkvm_do_nfsservctl, "NFSSERVCTL" },
  [__NR_getpmsg]                = { elkvm_do_getpmsg, "GETPMSG" },
  [__NR_putpmsg]                = { elkvm_do_putpmsg, "PUTPMSG" },
  [__NR_afs_syscall]            = { elkvm_do_afs_syscall, "AFS SYSCALL" },
  [__NR_tuxcall]                = { elkvm_do_tuxcall, "TUXCALL" },
  [__NR_security]               = { elkvm_do_security, "SECURITY" },
  [__NR_gettid]                 = { elkvm_do_gettid, "GETTID" },
  [__NR_readahead]              = { elkvm_do_readahead, "READAHEAD" },
  [__NR_setxattr]               = { elkvm_do_setxattr, "SETXATTR" },
  [__NR_lsetxattr]              = { elkvm_do_lsetxattr, "LETSETXATTR" },
  [__NR_fsetxattr]              = { elkvm_do_fsetxattr, "FSETXATTR" },
  [__NR_getxattr]               = { elkvm_do_getxattr, "GETXATTR" },
  [__NR_lgetxattr]              = { elkvm_do_lgetxattr, "LGETXATTR" },
  [__NR_fgetxattr]              = { elkvm_do_fgetxattr, "FGETXATTR" },
  [__NR_listxattr]              = { elkvm_do_listxattr, "LISTXATTR" },
  [__NR_llistxattr]             = { elkvm_do_llistxattr, "LLISTXATTR" },
  [__NR_flistxattr]             = { elkvm_do_flistxattr, "FLISTXATTR" },
  [__NR_removexattr]            = { elkvm_do_removexattr, "REMOVEXATTR" },
  [__NR_lremovexattr]           = { elkvm_do_lremovexattr, "LREMOVEXATTR" },
  [__NR_fremovexattr]           = { elkvm_do_fremovexattr, "FREMOVEXATTR" },
  [__NR_tkill]                  = { elkvm_do_tkill, "TKILL" },
  [__NR_time]                   = { elkvm_do_time, "TIME" },
  [__NR_futex]                  = { elkvm_do_futex, "FUTEX" },
  [__NR_sched_setaffinity]      = { elkvm_do_sched_setaffinity, "SCHED SETAFFINITY" },
  [__NR_sched_getaffinity]      = { elkvm_do_sched_getaffinity, "SCHED GETAFFINITY" },
  [__NR_set_thread_area]        = { elkvm_do_set_thread_area, "SET THREAD AREA" },
  [__NR_io_setup]               = { elkvm_do_io_setup, "IO SETUP" },
  [__NR_io_destroy]             = { elkvm_do_io_destroy, "IO DESTROY" },
  [__NR_io_getevents]           = { elkvm_do_getevents, "IO GETEVENTS" },
  [__NR_io_submit]              = { elkvm_do_submit, "IO SUBMIT" },
  [__NR_io_cancel]              = { elkvm_do_cancel, "IO CANCEL" },
  [__NR_get_thread_area]        = { elkvm_do_get_thread_area, "GET THREAD AREA" },
  [__NR_lookup_dcookie]         = { elkvm_do_lookup_dcookie, "LOOKUP DCOOKIE" },
  [__NR_epoll_create]           = { elkvm_do_epoll_create, "EPOLL CREATE" },
  [__NR_epoll_ctl_old]          = { elkvm_do_epoll_ctl_old, "EPOLL CTL OLD" },
  [__NR_epoll_wait_old]         = { elkvm_do_epoll_wait_old, "EPOLL WAIT OLD" },
  [__NR_remap_file_pages]       = { elkvm_do_remap_file_pages, "REMAP FILE PAGES" },
  [__NR_getdents64]             = { elkvm_do_getdents64, "GETDENTS64" },
  [__NR_set_tid_address]        = { elkvm_do_set_tid_address, "SET TID ADDRESS" },
  [__NR_restart_syscall]        = { elkvm_do_restart_syscall, "RESTART SYSCALL" },
  [__NR_semtimedop]             = { elkvm_do_semtimedop, "SEMTIMEDOP" },
  [__NR_fadvise64]              = { elkvm_do_fadive64, "FADVISE64" },
  [__NR_timer_create]           = { elkvm_do_timer_create, "TIMER CREATE" },
  [__NR_timer_settime]          = { elkvm_do_timer_settime, "TIMER SETTIME" },
  [__NR_timer_gettime]          = { elkvm_do_timer_gettime, "TIMER GETTIME" },
  [__NR_timer_getoverrun]       = { elkvm_do_timer_getoverrun, "TIMER GETOVERRUN" },
  [__NR_timer_delete]           = { elkvm_do_timer_delete, "TIMER DELETE" },
  [__NR_clock_settime]   = { elkvm_do_clock_settime, "CLOCK SETTIME" },
  [__NR_clock_gettime]   = { elkvm_do_clock_gettime, "CLOCK GETTIME" },
  [__NR_clock_getres]    = { elkvm_do_clock_getres, "CLOCK GETRES" },
  [__NR_clock_nanosleep] = { elkvm_do_clock_nanosleep, "CLOCK NANOSLEEP" },
  [__NR_exit_group]      = { elkvm_do_exit_group, "EXIT GROUP" },
  [__NR_epoll_wait]      = { elkvm_do_epoll_wait, "EPOLL WAIT" },
  [__NR_epoll_ctl]       = { elkvm_do_epoll_ctl, "EPOLL CTL" },
  [__NR_tgkill]          = { elkvm_do_tgkill, "TGKILL" },
  [__NR_utimes]          = { elkvm_do_utimes, "UTIMES" },
  [__NR_vserver]         = { elkvm_do_vserver, "VSERVER" },
  [__NR_mbind]           = { elkvm_do_mbind, "MBIND" },
  [__NR_set_mempolicy]   = { elkvm_do_mpolicy, "SET MPOLICY" },
  [__NR_get_mempolicy]   = { elkvm_do_get_mempolicy, "GET MEMPOLICY" },
  [__NR_mq_open]         = { elkvm_do_mq_open, "MQ OPEN" },
  [__NR_mq_unlink]       = { elkvm_do_mq_unlink, "MQ UNLINK" },
  [__NR_mq_timedsend]    = { elkvm_do_mq_timedsend, "MQ TIMEDSEND" },
  [__NR_mq_timedreceive] = { elkvm_do_mq_timedreceive, "MQ TIMEDRECEIVE" },
  [__NR_mq_notify]       = { elkvm_do_mq_notify, "MQ NOTIFY" },
  [__NR_mq_getsetattr]   = { elkvm_do_getsetattr, "MQ GETSETATTR" },
  [__NR_kexec_load]      = { elkvm_do_kexec_load, "KEXEC LOAD" },
  [__NR_waitid]          = { elkvm_do_waitid, "WAITID" },
  [__NR_add_key]         = { elkvm_do_add_key, "ADD KEY" },
  [__NR_request_key]     = { elkvm_do_request_key, "REQUEST KEY" },
  [__NR_keyctl]          = { elkvm_do_keyctl, "KEYCTL" },
  [__NR_ioprio_set]      = { elkvm_do_ioprio_set, "IOPRIO SET" },
  [__NR_ioprio_get]      = { elkvm_do_ioprio_get, "IOPRIO GET" },
  [__NR_inotify_init]    = { elkvm_do_inotify_init, "INOTIFY INIT" },
  [__NR_inotify_add_watch] = { elkvm_do_inotify_add_watch, "INOTIFY ADD WATCH" },
  [__NR_inotify_rm_watch]  = { elkvm_do_inotify_rm_watch, "INOTIFY RM WATCH" },
  [__NR_migrate_pages]     = { elkvm_do_migrate_pages, "MIGRATE PAGES" },
  [__NR_openat]          = { elkvm_do_openat, "OPENAT" },

};

#ifdef __cplusplus
}
#endif

