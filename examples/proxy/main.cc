#include <asm/unistd_64.h>
#include <errno.h>
#include <fcntl.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <linux/futex.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#include <elkvm/elkvm.h>
#include <elkvm/kvm.h>
#include <elkvm/vcpu.h>
#include <elkvm/stack.h>

#include <stdint.h>
#include <smmintrin.h>

extern char **environ;
struct elkvm_opts elkvm;
struct kvm_vm vm;
bool inspect;

uint64_t rcs;

uint32_t fastcrc(uint64_t *ptr, size_t len) {
    uint32_t crc = 0;

    for (size_t i = 0; i < len; i = i + sizeof (uint64_t))
        crc = _mm_crc32_u64(crc, *ptr++);

    return crc;
}

uint64_t inspect_regs() {
  struct kvm_vcpu *vcpu = elkvm_vcpu_get(&vm, 0);
  uint64_t *r = (uint64_t *) &vcpu->regs;
  int bytes = sizeof(struct kvm_regs) + sizeof(struct kvm_sregs);
  return fastcrc(r, bytes);

//  int words = bytes / sizeof(uint32_t);
//
//  uint64_t sum1 = 0;
//  uint64_t sum2 = 0;
//
//  for(int i = 0; i < words; i++) {
//    sum1 = (sum1 + r[i]) % 0xFFFFFFFF;
//    sum2 = (sum2 + sum1) % 0xFFFFFFFF;
//  }
//
//  return (sum2 << 32) | sum1;
}

//int bp_cb(struct kvm_vm *vm) {
//  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);
//  vcpu->regs.rax = 4;
//  vcpu->regs.rdx = 5;
//  return 0;
//}
//
long pass_read(int fd, void *buf, size_t count) {
  if(inspect) {
    rcs += inspect_regs();
  }
  return read(fd, buf, count);
}

long pass_write(int fd, void *buf, size_t count) {
  if(inspect) {
    rcs += inspect_regs();
  }
  return write(fd, buf, count);
}

long pass_open(const char *pathname, int flags, mode_t mode) {
  if(inspect) {
    rcs += inspect_regs();
  }
  return open(pathname, flags, mode);
}

long pass_close(int fd) {
  if(inspect) {
    rcs += inspect_regs();
  }
  return close(fd);
}

long pass_stat(const char *path, struct stat *buf) {
  if(inspect) {
    rcs += inspect_regs();
  }
  return stat(path, buf);
}

long pass_fstat(int fd, struct stat *buf) {
  if(inspect) {
    rcs += inspect_regs();
  }
  return fstat(fd, buf);
}

long pass_lstat(const char *path, struct stat *buf) {
  if(inspect) {
    rcs += inspect_regs();
  }
  return lstat(path, buf);
}

long pass_lseek(int fd, off_t offset, int whence) {
  return lseek(fd, offset, whence);
}

long pass_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset,
    struct region_mapping *mapping) {
  if(inspect) {
    rcs += inspect_regs();
  }

  mapping->guest_virt = (uint64_t)mapping->host_p;
  return 0;
}

long allow_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
  return 1;
}

long pass_munmap(struct region_mapping *mapping) {
  if(inspect) {
    rcs += inspect_regs();
  }
  return munmap(mapping->host_p, mapping->length);
}

long pass_readv(int fd, struct iovec *iov, int iovcnt) {
  if(inspect) {
    rcs += inspect_regs();
  }
  return readv(fd, iov, iovcnt);
}

long pass_writev(int fd, struct iovec *iov, int iovcnt) {
  if(inspect) {
    rcs += inspect_regs();
  }
  return writev(fd, iov, iovcnt);
}

long pass_access(const char *pathname, int mode) {
  if(inspect) {
    rcs += inspect_regs();
  }
  return access(pathname, mode);
}

long pass_pipe(int pipefds[2]) {
  if(inspect) {
    rcs += inspect_regs();
  }
  return pipe(pipefds);
}

long pass_dup(int oldfd) {
  if(inspect) {
    rcs += inspect_regs();
  }
  return dup(oldfd);
}

long pass_getpid() {
  if(inspect) {
    rcs += inspect_regs();
  }
  return getpid();
}

long pass_getuid() {
  if(inspect) {
    rcs += inspect_regs();
  }
  return getuid();
}

long pass_getgid() {
  if(inspect) {
    rcs += inspect_regs();
  }
  return getgid();
}

long pass_geteuid() {
  if(inspect) {
    rcs += inspect_regs();
  }
  return geteuid();
}

long pass_getegid() {
  if(inspect) {
    rcs += inspect_regs();
  }
  return getegid();
}

long pass_uname(struct utsname *buf) {
  if(inspect) {
    rcs += inspect_regs();
  }
	return uname(buf);
}

long pass_fcntl(int fd, int cmd, ...) {
  va_list ap;
  long result = 0;
  void *parg = NULL;
  int iarg = 0;

  va_start(ap, cmd);
  switch(cmd) {
    case F_GETOWN_EX:
    case F_SETOWN_EX:
    case F_GETLK:
    case F_SETLK:
    case F_SETLKW:
      parg = va_arg(ap, void *);
      result = fcntl(fd, cmd, parg);
      break;
    default:
      iarg = va_arg(ap, int);
      result = fcntl(fd, cmd, iarg);
      break;
  }

  va_end(ap);
  return result;
}

long pass_truncate(const char *path, off_t length) {
  if(inspect) {
    rcs += inspect_regs();
  }
  return truncate(path, length);
}

long pass_ftruncate(int fd, off_t length) {
  if(inspect) {
    rcs += inspect_regs();
  }
  return ftruncate(fd, length);
}

char *pass_getcwd(char *buf, size_t size) {
  if(inspect) {
    rcs += inspect_regs();
  }
  return getcwd(buf, size);
}

long pass_mkdir(const char *pathname, mode_t mode) {
  if(inspect) {
    rcs += inspect_regs();
  }
  return mkdir(pathname, mode);
}

long pass_unlink(const char *pathname) {
  if(inspect) {
    rcs += inspect_regs();
  }
  return unlink(pathname);
}

long pass_readlink(const char *path, char *buf, size_t bufsiz) {
  if(inspect) {
    rcs += inspect_regs();
  }
  return readlink(path, buf, bufsiz);
}

long pass_gettimeofday(struct timeval *tv, struct timezone *tz) {
  if(inspect) {
    rcs += inspect_regs();
  }
  return gettimeofday(tv, tz);
}

long pass_getrusage(int who, struct rusage *usage) {
  if(inspect) {
    rcs += inspect_regs();
  }
  return getrusage(who, usage);
}

long pass_gettid() {
  if(inspect) {
    rcs += inspect_regs();
  }
  return syscall(__NR_gettid);
}

long pass_time(time_t *t) {
  if(inspect) {
    rcs += inspect_regs();
  }
  return time(t);
}

long pass_futex(int *uaddr, int op, int val, const struct timespec *timeout,
    int *uaddr2, int val3) {
  if(inspect) {
    rcs += inspect_regs();
  }
  return syscall(__NR_futex, uaddr, op, val, timeout, uaddr2, val3);
}

long pass_clock_gettime(clockid_t clk_id, struct timespec *tp) {
  if(inspect) {
    rcs += inspect_regs();
  }
  return clock_gettime(clk_id, tp);
}

void pass_exit_group(int status) {
  if(inspect) {
    rcs += inspect_regs();
  }
  exit(status);
}

long pass_tgkill(int tgid, int tid, int sig) {
  if(inspect) {
    rcs += inspect_regs();
  }
  return syscall(__NR_tgkill, tgid, tid, sig);
}

struct elkvm_handlers example_handlers = {
	.read = pass_read,
	.write = pass_write,
	.open = pass_open,
	.close = pass_close,
	.stat = pass_stat,
	.fstat = pass_fstat,
	.lstat = pass_lstat,
	.poll = NULL,
	.lseek = pass_lseek,
	.mmap = pass_mmap,
  .mprotect = NULL,
  .munmap = pass_munmap,
  /* ... */
  .sigaction = allow_sigaction,
  .sigprocmask = NULL,
  /* ... */
  .readv = pass_readv,
  .writev = pass_writev,
  .access = pass_access,
  .pipe = pass_pipe,
  .dup = pass_dup,
  /* ... */
  .nanosleep = NULL,
  /* ... */
  .getpid = pass_getpid,
  /* ... */
  .getuid  = pass_getuid,
  .getgid  = pass_getgid,
  .geteuid = pass_geteuid,
  .getegid = pass_getegid,
	/* ... */
	.uname = pass_uname,
  .fcntl = pass_fcntl,
  .truncate = pass_truncate,
  .ftruncate = pass_ftruncate,
  .getcwd = pass_getcwd,
  .mkdir = pass_mkdir,
  .unlink = pass_unlink,
  .readlink = pass_readlink,
  /* ... */
  .gettimeofday = pass_gettimeofday,
  .getrusage = pass_getrusage,
  .times = NULL,
  /* ... */
  .gettid = pass_gettid,
  .time = pass_time,
  .futex = pass_futex,
  /* ... */
  .clock_gettime = pass_clock_gettime,
  .exit_group = pass_exit_group,
  .tgkill = pass_tgkill,

  .bp_callback = NULL,
};

void print_usage(int argc, char **argv) {
  printf("Usage: %s [-d] [-s] binary [binaryopts]\n", argv[0]);
  exit(EXIT_FAILURE);
}

extern char *optarg;
extern int optind;
extern int opterr;

int main(int argc, char **argv) {

  int opt;
  int err;
  int debug = 0;
  int gdb = 0;
  int myopts = 1;
  opterr = 0;
  inspect = false;
  struct kvm_vcpu *vcpu = NULL;

  while((opt = getopt(argc, argv, "+drD")) != -1) {
    switch(opt) {
      case 'd':
        debug = 1;
        myopts++;
        break;
      case 'r':
        inspect = true;
        myopts++;
        break;
      case 'D':
        gdb = 1;
        myopts++;
        break;
    }
  }

  if(optind >= argc) {
    print_usage(argc, argv);
  }

  char *binary = argv[myopts];
  char **binargv = &argv[myopts];
  int binargc = argc - myopts;

	err = elkvm_init(&elkvm, binargc, binargv, environ);
	if(err) {
    if(errno == -ENOENT) {
      printf("/dev/kvm seems not to exist. Check your KVM installation!\n");
    }
    if(errno == -EACCES) {
      printf("Access to /dev/kvm was denied. Check if you belong to the 'kvm' group!\n");
    }
		printf("ERROR initializing VM errno: %i Msg: %s\n", -err, strerror(-err));
		return -1;
	}


//  printf("LOADING binary %s with %i opts\n", binary, binargc);
//  for(int i = 0; i < binargc; i++) {
//    printf("binargv[%i] %s\n", i, binargv[i]);
//  }

	err = kvm_vm_create(&elkvm, &vm, VM_MODE_X86_64, 1, 1024*1024, &example_handlers, binary);
	if(err) {
		printf("ERROR creating VM errno: %i Msg: %s\n", -err, strerror(-err));
		return -1;
	}

  vcpu = elkvm_vcpu_get(&vm, 0);

  if(debug) {
    err = elkvm_set_debug(&vm);
    if(err) {
      printf("ERROR putting VM in debug mode errno: %i Msg: %s\n", -err, strerror(-err));
      return -1;
    }
  }

  if(gdb) {
    //gdbstub will take it from here!
    elkvm_gdbstub_init(&vm);
    return 0;
  }

	err = kvm_vcpu_loop(vcpu);
	if(err) {
		printf("ERROR running VCPU errno: %i Msg: %s\n", -err, strerror(-err));
		return -1;
	}

	err = elkvm_cleanup(&elkvm);
	if(err) {
		printf("ERROR cleaning up errno: %i Msg: %s\n", -err, strerror(-err));
		return -1;
	}

	printf("DONE\n");
  if(inspect) {
    printf("Total RCS: %lu\n", rcs);
  }
	return 0;
}

