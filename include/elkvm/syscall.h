#pragma once

#include <asm/unistd_64.h>

#include <memory>

#define ELKVM_HYPERCALL_SYSCALL   1
#define ELKVM_HYPERCALL_INTERRUPT 2

#define ELKVM_HYPERCALL_EXIT      0x42
#define NUM_SYSCALLS 313

namespace Elkvm {
  class VCPU;
  class VM;
}

/*
 * Interface for a platform-specific binary interface.
 * The ABI specifies where the syscall parameters come from.
 */
template <typename SYSCALL_TYPE>
class ABI
{
  public:
    typedef SYSCALL_TYPE paramtype;

    /*
     * Get n-th system call parameter from ABI register set.
     */
    static paramtype get_parameter(std::shared_ptr<Elkvm::VCPU> vcpu, unsigned pos);

    /*
     * Set the ABI-specific syscall return register to value.
     */
    static void set_syscall_return(std::shared_ptr<Elkvm::VCPU> vcpu, paramtype value);
};

class X86_64_ABI : public ABI <uint64_t>
{
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

  public:
    static ABI::paramtype
    get_parameter(std::shared_ptr<Elkvm::VCPU> vcpu, unsigned pos);

    static void
    set_syscall_return(std::shared_ptr<Elkvm::VCPU> vcpu, paramtype value);
};

// XXX: this needs to be adjusted for other platforms
typedef X86_64_ABI CURRENT_ABI;

long elkvm_do_read(Elkvm::VM *);
long elkvm_do_write(Elkvm::VM *);
long elkvm_do_open(Elkvm::VM *);
long elkvm_do_close(Elkvm::VM *);
long elkvm_do_stat(Elkvm::VM *);
long elkvm_do_fstat(Elkvm::VM *);
long elkvm_do_lstat(Elkvm::VM *);
long elkvm_do_poll(Elkvm::VM *);
long elkvm_do_lseek(Elkvm::VM *);
long elkvm_do_mmap(Elkvm::VM *);
long elkvm_do_mprotect(Elkvm::VM *);
long elkvm_do_munmap(Elkvm::VM *);
long elkvm_do_brk(Elkvm::VM *);
long elkvm_do_sigaction(Elkvm::VM *);
long elkvm_do_sigprocmask(Elkvm::VM *);
long elkvm_do_sigreturn(Elkvm::VM *);
long elkvm_do_ioctl(Elkvm::VM *);
long elkvm_do_pread64(Elkvm::VM *);
long elkvm_do_pwrite64(Elkvm::VM *);
long elkvm_do_readv(Elkvm::VM *);
long elkvm_do_writev(Elkvm::VM *);
long elkvm_do_access(Elkvm::VM *);
long elkvm_do_pipe(Elkvm::VM *);
long elkvm_do_select(Elkvm::VM *);
long elkvm_do_sched_yield(Elkvm::VM *);
long elkvm_do_mremap(Elkvm::VM *);
long elkvm_do_msync(Elkvm::VM *);
long elkvm_do_mincore(Elkvm::VM *);
long elkvm_do_madvise(Elkvm::VM *);
long elkvm_do_shmget(Elkvm::VM *);
long elkvm_do_shmat(Elkvm::VM *);
long elkvm_do_shmctl(Elkvm::VM *);
long elkvm_do_dup(Elkvm::VM *);
long elkvm_do_dup2(Elkvm::VM *);
long elkvm_do_pause(Elkvm::VM *);
long elkvm_do_nanosleep(Elkvm::VM *);
long elkvm_do_getitimer(Elkvm::VM *);
long elkvm_do_alarm(Elkvm::VM *);
long elkvm_do_setitimer(Elkvm::VM *);
long elkvm_do_getpid(Elkvm::VM *);
long elkvm_do_sendfile(Elkvm::VM *);
long elkvm_do_socket(Elkvm::VM *);
long elkvm_do_connect(Elkvm::VM *);
long elkvm_do_accept(Elkvm::VM *);
long elkvm_do_sendto(Elkvm::VM *);
long elkvm_do_recvfrom(Elkvm::VM *);
long elkvm_do_sendmsg(Elkvm::VM *);
long elkvm_do_recvmsg(Elkvm::VM *);
long elkvm_do_shutdown(Elkvm::VM *);
long elkvm_do_bind(Elkvm::VM *);
long elkvm_do_listen(Elkvm::VM *);
long elkvm_do_getsockname(Elkvm::VM *);
long elkvm_do_getpeername(Elkvm::VM *);
long elkvm_do_socketpair(Elkvm::VM *);
long elkvm_do_setsockopt(Elkvm::VM *);
long elkvm_do_getsockopt(Elkvm::VM *);
long elkvm_do_clone(Elkvm::VM *);
long elkvm_do_fork(Elkvm::VM *);
long elkvm_do_vfork(Elkvm::VM *);
long elkvm_do_execve(Elkvm::VM *);
long elkvm_do_exit(Elkvm::VM *);
long elkvm_do_wait4(Elkvm::VM *);
long elkvm_do_kill(Elkvm::VM *);
long elkvm_do_uname(Elkvm::VM *);
long elkvm_do_semget(Elkvm::VM *);
long elkvm_do_semop(Elkvm::VM *);
long elkvm_do_semctl(Elkvm::VM *);
long elkvm_do_shmdt(Elkvm::VM *);
long elkvm_do_msgget(Elkvm::VM *);
long elkvm_do_msgsnd(Elkvm::VM *);
long elkvm_do_msgrcv(Elkvm::VM *);
long elkvm_do_msgctl(Elkvm::VM *);
long elkvm_do_fcntl(Elkvm::VM *);
long elkvm_do_flock(Elkvm::VM *);
long elkvm_do_fsync(Elkvm::VM *);
long elkvm_do_fdatasync(Elkvm::VM *);
long elkvm_do_truncate(Elkvm::VM *);
long elkvm_do_ftruncate(Elkvm::VM *);
long elkvm_do_getdents(Elkvm::VM *);
long elkvm_do_getcwd(Elkvm::VM *);
long elkvm_do_chdir(Elkvm::VM *);
long elkvm_do_fchdir(Elkvm::VM *);
long elkvm_do_rename(Elkvm::VM *);
long elkvm_do_mkdir(Elkvm::VM *);
long elkvm_do_rmdir(Elkvm::VM *);
long elkvm_do_creat(Elkvm::VM *);
long elkvm_do_link(Elkvm::VM *);
long elkvm_do_unlink(Elkvm::VM *);
long elkvm_do_symlink(Elkvm::VM *);
long elkvm_do_readlink(Elkvm::VM *);
long elkvm_do_chmod(Elkvm::VM *);
long elkvm_do_fchmod(Elkvm::VM *);
long elkvm_do_chown(Elkvm::VM *);
long elkvm_do_fchown(Elkvm::VM *);
long elkvm_do_lchown(Elkvm::VM *);
long elkvm_do_umask(Elkvm::VM *);
long elkvm_do_gettimeofday(Elkvm::VM *);
long elkvm_do_getrlimit(Elkvm::VM *);
long elkvm_do_getrusage(Elkvm::VM *);
long elkvm_do_sysinfo(Elkvm::VM *);
long elkvm_do_times(Elkvm::VM *);
long elkvm_do_ptrace(Elkvm::VM *);
long elkvm_do_getuid(Elkvm::VM *);
long elkvm_do_syslog(Elkvm::VM *);
long elkvm_do_getgid(Elkvm::VM *);
long elkvm_do_setuid(Elkvm::VM *);
long elkvm_do_setgid(Elkvm::VM *);
long elkvm_do_geteuid(Elkvm::VM *);
long elkvm_do_getegid(Elkvm::VM *);
long elkvm_do_setpgid(Elkvm::VM *);
long elkvm_do_getppid(Elkvm::VM *);
long elkvm_do_getpgrp(Elkvm::VM *);
long elkvm_do_setsid(Elkvm::VM *);
long elkvm_do_setreuid(Elkvm::VM *);
long elkvm_do_setregid(Elkvm::VM *);
long elkvm_do_getgroups(Elkvm::VM *);
long elkvm_do_setgroups(Elkvm::VM *);
long elkvm_do_setresuid(Elkvm::VM *);
long elkvm_do_getresuid(Elkvm::VM *);
long elkvm_do_setresgid(Elkvm::VM *);
long elkvm_do_getresgid(Elkvm::VM *);
long elkvm_do_getpgid(Elkvm::VM *);
long elkvm_do_setfsuid(Elkvm::VM *);
long elkvm_do_setfsgid(Elkvm::VM *);
long elkvm_do_getsid(Elkvm::VM *);
long elkvm_do_capget(Elkvm::VM *);
long elkvm_do_capset(Elkvm::VM *);
long elkvm_do_rt_sigpending(Elkvm::VM *);
long elkvm_do_rt_sigtimedwait(Elkvm::VM *);
long elkvm_do_rt_sigqueueinfo(Elkvm::VM *);
long elkvm_do_rt_sigsuspend(Elkvm::VM *);
long elkvm_do_sigaltstack(Elkvm::VM *);
long elkvm_do_utime(Elkvm::VM *);
long elkvm_do_mknod(Elkvm::VM *);
long elkvm_do_uselib(Elkvm::VM *);
long elkvm_do_personality(Elkvm::VM *);
long elkvm_do_ustat(Elkvm::VM *);
long elkvm_do_statfs(Elkvm::VM *);
long elkvm_do_fstatfs(Elkvm::VM *);
long elkvm_do_sysfs(Elkvm::VM *);
long elkvm_do_getpriority(Elkvm::VM *);
long elkvm_do_setpriority(Elkvm::VM *);
long elkvm_do_sched_setparam(Elkvm::VM *);
long elkvm_do_sched_getparam(Elkvm::VM *);
long elkvm_do_sched_setscheduler(Elkvm::VM *);
long elkvm_do_sched_getscheduler(Elkvm::VM *);
long elkvm_do_sched_get_priority_max(Elkvm::VM *);
long elkvm_do_sched_get_priority_min(Elkvm::VM *);
long elkvm_do_sched_rr_get_interval(Elkvm::VM *);
long elkvm_do_mlock(Elkvm::VM *);
long elkvm_do_munlock(Elkvm::VM *);
long elkvm_do_mlockall(Elkvm::VM *);
long elkvm_do_munlockall(Elkvm::VM *);
long elkvm_do_vhangup(Elkvm::VM *);
long elkvm_do_modify_ldt(Elkvm::VM *);
long elkvm_do_pivot_root(Elkvm::VM *);
long elkvm_do_sysctl(Elkvm::VM *);
long elkvm_do_prctl(Elkvm::VM *);
long elkvm_do_arch_prctl(Elkvm::VM *);
long elkvm_do_adjtimex(Elkvm::VM *);
long elkvm_do_setrlimit(Elkvm::VM *);
long elkvm_do_chroot(Elkvm::VM *);
long elkvm_do_sync(Elkvm::VM *);
long elkvm_do_acct(Elkvm::VM *);
long elkvm_do_settimeofday(Elkvm::VM *);
long elkvm_do_mount(Elkvm::VM *);
long elkvm_do_umount2(Elkvm::VM *);
long elkvm_do_swapon(Elkvm::VM *);
long elkvm_do_swapoff(Elkvm::VM *);
long elkvm_do_reboot(Elkvm::VM *);
long elkvm_do_sethostname(Elkvm::VM *);
long elkvm_do_setdomainname(Elkvm::VM *);
long elkvm_do_iopl(Elkvm::VM *);
long elkvm_do_ioperm(Elkvm::VM *);
long elkvm_do_create_module(Elkvm::VM *);
long elkvm_do_init_module(Elkvm::VM *);
long elkvm_do_delete_module(Elkvm::VM *);
long elkvm_do_get_kernel_syms(Elkvm::VM *);
long elkvm_do_query_module(Elkvm::VM *);
long elkvm_do_quotactl(Elkvm::VM *);
long elkvm_do_nfsservctl(Elkvm::VM *);
long elkvm_do_getpmsg(Elkvm::VM *);
long elkvm_do_putpmsg(Elkvm::VM *);
long elkvm_do_afs_syscall(Elkvm::VM *);
long elkvm_do_tuxcall(Elkvm::VM *);
long elkvm_do_security(Elkvm::VM *);
long elkvm_do_gettid(Elkvm::VM *);
long elkvm_do_readahead(Elkvm::VM *);
long elkvm_do_setxattr(Elkvm::VM *);
long elkvm_do_lsetxattr(Elkvm::VM *);
long elkvm_do_fsetxattr(Elkvm::VM *);
long elkvm_do_getxattr(Elkvm::VM *);
long elkvm_do_lgetxattr(Elkvm::VM *);
long elkvm_do_fgetxattr(Elkvm::VM *);
long elkvm_do_listxattr(Elkvm::VM *);
long elkvm_do_llistxattr(Elkvm::VM *);
long elkvm_do_flistxattr(Elkvm::VM *);
long elkvm_do_removexattr(Elkvm::VM *);
long elkvm_do_lremovexattr(Elkvm::VM *);
long elkvm_do_fremovexattr(Elkvm::VM *);
long elkvm_do_tkill(Elkvm::VM *);
long elkvm_do_time(Elkvm::VM *);
long elkvm_do_futex(Elkvm::VM *);
long elkvm_do_sched_setaffinity(Elkvm::VM *);
long elkvm_do_sched_getaffinity(Elkvm::VM *);
long elkvm_do_set_thread_area(Elkvm::VM *);
long elkvm_do_io_setup(Elkvm::VM *);
long elkvm_do_io_destroy(Elkvm::VM *);
long elkvm_do_getevents(Elkvm::VM *);
long elkvm_do_submit(Elkvm::VM *);
long elkvm_do_cancel(Elkvm::VM *);
long elkvm_do_get_thread_area(Elkvm::VM *);
long elkvm_do_lookup_dcookie(Elkvm::VM *);
long elkvm_do_epoll_create(Elkvm::VM *);
long elkvm_do_epoll_ctl_old(Elkvm::VM *);
long elkvm_do_epoll_wait_old(Elkvm::VM *);
long elkvm_do_remap_file_pages(Elkvm::VM *);
long elkvm_do_getdents64(Elkvm::VM *);
long elkvm_do_set_tid_address(Elkvm::VM *);
long elkvm_do_restart_syscall(Elkvm::VM *);
long elkvm_do_semtimedop(Elkvm::VM *);
long elkvm_do_fadive64(Elkvm::VM *);
long elkvm_do_timer_create(Elkvm::VM *);
long elkvm_do_timer_settime(Elkvm::VM *);
long elkvm_do_timer_gettime(Elkvm::VM *);
long elkvm_do_timer_getoverrun(Elkvm::VM *);
long elkvm_do_timer_delete(Elkvm::VM *);
long elkvm_do_clock_settime(Elkvm::VM *);
long elkvm_do_clock_gettime(Elkvm::VM *);
long elkvm_do_clock_getres(Elkvm::VM *);
long elkvm_do_clock_nanosleep(Elkvm::VM *);
long elkvm_do_exit_group(Elkvm::VM *);
long elkvm_do_epoll_wait(Elkvm::VM *);
long elkvm_do_epoll_ctl(Elkvm::VM *);
long elkvm_do_tgkill(Elkvm::VM *);
long elkvm_do_utimes(Elkvm::VM *);
long elkvm_do_vserver(Elkvm::VM *);
long elkvm_do_mbind(Elkvm::VM *);
long elkvm_do_mpolicy(Elkvm::VM *);
long elkvm_do_get_mempolicy(Elkvm::VM *);
long elkvm_do_mq_open(Elkvm::VM *);
long elkvm_do_mq_unlink(Elkvm::VM *);
long elkvm_do_mq_timedsend(Elkvm::VM *);
long elkvm_do_mq_timedreceive(Elkvm::VM *);
long elkvm_do_mq_notify(Elkvm::VM *);
long elkvm_do_getsetattr(Elkvm::VM *);
long elkvm_do_kexec_load(Elkvm::VM *);
long elkvm_do_waitid(Elkvm::VM *);
long elkvm_do_add_key(Elkvm::VM *);
long elkvm_do_request_key(Elkvm::VM *);
long elkvm_do_keyctl(Elkvm::VM *);
long elkvm_do_ioprio_set(Elkvm::VM *);
long elkvm_do_ioprio_get(Elkvm::VM *);
long elkvm_do_inotify_init(Elkvm::VM *);
long elkvm_do_inotify_add_watch(Elkvm::VM *);
long elkvm_do_inotify_rm_watch(Elkvm::VM *);
long elkvm_do_migrate_pages(Elkvm::VM *);
long elkvm_do_openat(Elkvm::VM *);

