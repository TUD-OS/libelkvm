#include <elkvm/elkvm.h>
#include <elkvm/syscall.h>

long elkvm_do_poll(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_sigreturn(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_pread64(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_pwrite64(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_select(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_sched_yield(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_msync(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_mincore(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_madvise(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_shmget(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_shmat(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_shmctl(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_dup2(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_pause(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_getitimer(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_alarm(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_setitimer(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_clone(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_fork(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_vfork(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_execve(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_exit(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_wait4(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_kill(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_semget(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_semop(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_semctl(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_shmdt(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_msgget(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_msgsnd(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_msgrcv(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_msgctl(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_flock(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_fsync(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_fdatasync(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_rename(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_rmdir(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_creat(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_link(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_symlink(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_chmod(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_fchmod(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_chown(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_fchown(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_lchown(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_umask(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_getrlimit(Elkvm::VM *) {
  /* XXX implement again! */
    UNIMPLEMENTED_SYSCALL;
//  CURRENT_ABI::paramtype resource = 0x0;
//  CURRENT_ABI::paramtype rlim_p = 0x0;
//  struct rlimit *rlim = NULL;
//
//  vmi->unpack_syscall(&resource, &rlim_p);
//
//  assert(rlim_p != 0x0);
//  rlim = reinterpret_cast<struct rlimit *>(vmi->get_region_manager()->get_pager().get_host_p(rlim_p));
//
//  memcpy(rlim, &vm->rlimits[resource], sizeof(struct rlimit));
//  if(vmi->debug_mode()) {
//    printf("GETRLIMIT with resource: %li rlim: 0x%lx (%p)\n",
//        resource, rlim_p, rlim);
//  }
//
//  return 0;
}

long elkvm_do_sysinfo(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_ptrace(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_syslog(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_setuid(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_setgid(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_setpgid(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_getppid(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_getpgrp(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_setsid(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_setreuid(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_setregid(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_getgroups(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_setgroups(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_setresuid(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_getresuid(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_setresgid(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_getresgid(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_getpgid(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_setfsuid(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_setfsgid(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_getsid(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_capget(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_capset(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_rt_sigpending(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_rt_sigtimedwait(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_rt_sigqueueinfo(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_rt_sigsuspend(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_sigaltstack(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_utime(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_mknod(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_uselib(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_personality(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_ustat(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_fstatfs(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_sysfs(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_getpriority(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_setpriority(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_sched_setparam(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_sched_getparam(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_sched_setscheduler(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_sched_getscheduler(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_sched_get_priority_max(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_sched_get_priority_min(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_sched_rr_get_interval(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_mlock(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_munlock(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_mlockall(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_munlockall(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_vhangup(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_modify_ldt(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_pivot_root(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_sysctl(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_prctl(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_adjtimex(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_setrlimit(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_chroot(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_sync(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_acct(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_settimeofday(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_mount(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_umount2(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_swapon(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_swapoff(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_reboot(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_sethostname(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_setdomainname(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_iopl(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_ioperm(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_create_module(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_init_module(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_delete_module(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_get_kernel_syms(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_query_module(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_quotactl(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_nfsservctl(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_getpmsg(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_putpmsg(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_afs_syscall(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_tuxcall(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_security(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_readahead(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_setxattr(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_lsetxattr(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_fsetxattr(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_getxattr(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_lgetxattr(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_fgetxattr(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_listxattr(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_llistxattr(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_flistxattr(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_removexattr(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_lremovexattr(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_fremovexattr(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_tkill(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_sched_setaffinity(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_sched_getaffinity(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_set_thread_area(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_io_setup(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_io_destroy(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_getevents(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_submit(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_cancel(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_get_thread_area(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_lookup_dcookie(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_epoll_ctl_old(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_epoll_wait_old(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_remap_file_pages(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_getdents64(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_restart_syscall(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_semtimedop(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_fadive64(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_timer_create(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_timer_settime(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_timer_gettime(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_timer_getoverrun(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_timer_delete(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_clock_settime(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_clock_getres(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_clock_nanosleep(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_utimes(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_vserver(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_mbind(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_mpolicy(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_get_mempolicy(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_mq_open(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_mq_unlink(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_mq_timedsend(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_mq_timedreceive(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_mq_notify(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_getsetattr(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_kexec_load(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_waitid(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_add_key(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_request_key(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_keyctl(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_ioprio_set(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_ioprio_get(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_inotify_init(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_inotify_add_watch(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_inotify_rm_watch(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_migrate_pages(Elkvm::VM * vmi __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_set_robust_list(Elkvm::VM *vm __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}

long elkvm_do_get_robust_list(Elkvm::VM *vm __attribute__((unused))) {
  UNIMPLEMENTED_SYSCALL;
}
