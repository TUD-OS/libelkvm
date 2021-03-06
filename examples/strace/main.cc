//
// libelkvm - A library that allows execution of an ELF binary inside a virtual
// machine without a full-scale operating system
// Copyright (C) 2013-2015 Florian Pester <fpester@os.inf.tu-dresden.de>, Björn
// Döbel <doebel@os.inf.tu-dresden.de>,   economic rights: Technische Universitaet
// Dresden (Germany)
//
// This file is part of libelkvm.
//
// libelkvm is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// libelkvm is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with libelkvm.  If not, see <http://www.gnu.org/licenses/>.
//

#include <iostream>
#include <memory>
#include <cstring>

#include <elkvm/elkvm.h>
#include <elkvm/elkvm-log.h>
#include <elkvm/kvm.h>
#include <elkvm/regs.h>
#include <elkvm/syscall.h>
#include <elkvm/vcpu.h>

extern char **environment;

char const *syscalls[]= {
"read", "write", "open", "close", "stat", "fstat", "lstat",
"poll", "lseek", "mmap", "mprotect", "munmap", "brk", "rt_sigaction",
"rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64", "pwrite64",
"readv", "writev", "access", "pipe", "select", "sched_yield", "mremap",
"msync", "mincore", "madvise", "shmget", "shmat", "shmctl", "dup", "dup2",
"pause", "nanosleep", "getitimer", "alarm", "setitimer", "getpid", "sendfile",
"socket", "connect", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg",
"shutdown", "bind", "listen", "getsockname", "getpeername", "socketpair",
"setsockopt", "getsockopt", "clone", "fork", "vfork", "execve", "exit",
"wait4", "kill", "uname", "semget", "semop", "semctl", "shmdt", "msgget",
"msgsnd", "msgrcv", "msgctl", "fcntl", "flock", "fsync", "fdatasync",
"truncate", "ftruncate", "getdents", "getcwd", "chdir", "fchdir", "rename",
"mkdir", "rmdir", "creat", "link", "unlink", "symlink", "readlink", "chmod",
"fchmod", "chown", "fchown", "lchown", "umask", "gettimeofday", "getrlimit",
"getrusage", "sysinfo", "times", "ptrace", "getuid", "syslog", "getgid",
"setuid", "setgid", "geteuid", "getegid", "setpgid", "getppid", "getpgrp",
"setsid", "setreuid", "setregid", "getgroups", "setgroups", "setresuid",
"getresuid", "setresgid", "getresgid", "getpgid", "setfsuid", "setfsgid",
"getsid", "capget", "capset", "rt_sigpending", "rt_sigtimedwait",
"rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack", "utime", "mknod",
"uselib", "personality", "ustat", "statfs", "fstatfs", "sysfs", "getpriority",
"setpriority", "sched_setparam", "sched_getparam", "sched_setscheduler",
"sched_getscheduler", "sched_get_priority_max", "sched_get_priority_min",
"sched_rr_get_interval", "mlock", "munlock", "mlockall", "munlockall",
"vhangup", "modify_ldt", "pivot_root", "_sysctl", "prctl", "arch_prctl",
"adjtimex", "setrlimit", "chroot", "sync", "acct", "settimeofday", "mount",
"umount2", "swapon", "swapoff", "reboot", "sethostname", "setdomainname",
"iopl", "ioperm", "create_module", "init_module", "delete_module",
"get_kernel_syms", "query_module", "quotactl", "nfsservctl", "getpmsg",
"putpmsg", "afs_syscall", "tuxcall", "security", "gettid", "readahead",
"setxattr", "lsetxattr", "fsetxattr", "getxattr", "lgetxattr",
"fgetxattr", "listxattr", "llistxattr", "flistxattr", "removexattr",
"lremovexattr", "fremovexattr", "tkill", "time", "futex", "sched_setaffinity",
"sched_getaffinity", "set_thread_area", "io_setup", "io_destroy", "io_getevents",
"io_submit", "io_cancel", "get_thread_area", "lookup_dcookie", "epoll_create",
"epoll_ctl_old", "epoll_wait_old", "remap_file_pages", "getdents64",
"set_tid_address", "restart_syscall", "semtimedop", "fadvise64",
"timer_create", "timer_settime", "timer_gettime", "timer_getoverrun",
"timer_delete", "clock_settime", "clock_gettime", "clock_getres",
"clock_nanosleep", "exit_group", "epoll_wait", "epoll_ctl", "tgkill",
"utimes", "vserver", "mbind", "set_mempolicy", "get_mempolicy",
"mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify",
"mq_getsetattr", "kexec_load", "waitid", "add_key", "request_key", "keyctl",
"ioprio_set", "ioprio_get", "inotify_init", "inotify_add_watch",
"inotify_rm_watch", "migrate_pages", "openat", "mkdirat", "mknodat",
"fchownat", "futimesat", "newfstatat", "unlinkat", "renameat", "linkat",
"symlinkat", "readlinkat", "fchmodat", "faccessat", "pselect6", "ppoll",
"unshare", "set_robust_list", "get_robust_list", "splice", "tee", "sync_file_range",
"vmsplice", "move_pages", "utimensat", "epoll_pwait", "signalfd", "timerfd_create",
"eventfd", "fallocate", "timerfd_settime", "timerfd_gettime", "accept4", "signalfd4",
"eventfd2", "epoll_create1", "dup3", "pipe2", "inotify_init1", "preadv", "pwritev",
"rt_tgsigqueueinfo", "perf_event_open", "recvmmsg", "fanotify_init", "fanotify_mark",
"prlimit64", "name_to_handle_at", "open_by_handle_at", "clock_adjtime", "syncfs",
"sendmmsg", "setns", "getcpu", "process_vm_readv", "process_vm_writev", "kcmp",
"finit_module", "sched_setattr", "sched_getattr",
};

static long
strace_pre_handler(Elkvm::VM* vm __attribute__((unused)),
                   const std::shared_ptr<Elkvm::VCPU>& vcpu,
                   int eventtype)
{
  if (eventtype != ELKVM_HYPERCALL_SYSCALL)
    return 0;

  INFO() << "[ELKVM] System call '"
         << syscalls[vcpu->get_reg(Elkvm::Reg_t::rax)]
         << "'";
  return 0;
}


static long
strace_post_handler(Elkvm::VM* vm __attribute__((unused)),
                    const std::shared_ptr<Elkvm::VCPU>& vcpu,
                    int eventtype)
{
  if (eventtype != ELKVM_HYPERCALL_SYSCALL)
    return 0;

  INFO() << "[ELKVM]      = 0x" << std::hex
         << vcpu->get_reg(Elkvm::Reg_t::rax);
  return 0;
}

int main(int argc, char *argv[])
{
  if (argc < 2) {
    ERROR() << "No program argument given. Need at least a binary name.";
    abort();
  }

  INFO() << "[ELKVM] Launching" << std::endl;

  Elkvm::elkvm_opts opts;
  int err = elkvm_init(&opts, argc-1, &argv[1], environ);
  if (err) {
    ERROR() << "ERROR initializing ELKVM: " << strerror(-err);
    return 1;
  }

  Elkvm::hypercall_handlers strace_handlers = {
    .pre_handler = strace_pre_handler,
    .post_handler = strace_post_handler
  };

  std::shared_ptr<Elkvm::VM> vm = elkvm_vm_create(&opts, argv[1], 1, &strace_handlers);
  if (vm == nullptr) {
    ERROR() << "ERROR creating VM: " << strerror(errno);
    return 1;
  }

  err = vm->run();
  if (err) {
    ERROR() << "Error running vCPU: " << strerror(-err);
    return 1;
  }

  err = elkvm_cleanup(&opts);
  if (err) {
    ERROR() << "Error during cleanup: " << strerror(-err);
    return 1;
  }
  
  INFO() "[ELVKM] Terminating successfully.";

  return 0;
}
