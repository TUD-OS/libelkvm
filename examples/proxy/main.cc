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

#include <stdint.h>
#include <smmintrin.h>

extern char **environ;
struct elkvm_opts elkvm;
struct kvm_vm vm;
bool inspect;

long pass_read(int fd, void *buf, size_t count) {
  return read(fd, buf, count);
}

long pass_write(int fd, void *buf, size_t count) {
  return write(fd, buf, count);
}

long pass_open(const char *pathname, int flags, mode_t mode) {
  return open(pathname, flags, mode);
}

long pass_close(int fd) {
  return close(fd);
}

long pass_stat(const char *path, struct stat *buf) {
  return stat(path, buf);
}

long pass_fstat(int fd, struct stat *buf) {
  return fstat(fd, buf);
}

long pass_lstat(const char *path, struct stat *buf) {
  return lstat(path, buf);
}

long pass_lseek(int fd, off_t offset, int whence) {
  return lseek(fd, offset, whence);
}

long pass_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset,
    struct region_mapping *mapping) {
  if(!(flags & MAP_ANONYMOUS)) {
    off_t pos = lseek(fd, 0, SEEK_CUR);
    assert(pos >= 0 && "could not get current file position");
    int err = lseek(fd, offset, SEEK_SET);
    assert(err >= 0 && "seek set in pass_mmap failed");
    char *buf = (char *)mapping->host_p;
    printf("writing to %p\n", buf);
    ssize_t bytes = 0;
    size_t total = 0;
    errno = 0;
    while((total <= length) && (bytes = read(fd, buf, length)) > 0) {
      buf += bytes;
      total += bytes;
    }

    ssize_t rem = length - total;
    if(rem > 0) {
      printf("read %zd bytes of %zd bytes\n", total, length);
      printf("\nzeroing out %zd bytes at %p\n", rem, buf);
      memset(buf, 0, rem);
    }
    err = lseek(fd, pos, SEEK_SET);
    assert(err >= 0 && "could not restore file position");
  }

  if(mapping->guest_virt == 0x0) {
    mapping->guest_virt = (uint64_t)mapping->host_p;
  }
  return 0;
}

long allow_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
  return 1;
}

long pass_munmap(struct region_mapping *mapping) {
  return munmap(mapping->host_p, mapping->length);
}

long pass_readv(int fd, struct iovec *iov, int iovcnt) {
  return readv(fd, iov, iovcnt);
}

long pass_writev(int fd, struct iovec *iov, int iovcnt) {
  return writev(fd, iov, iovcnt);
}

long pass_access(const char *pathname, int mode) {
  return access(pathname, mode);
}

long pass_pipe(int pipefds[2]) {
  return pipe(pipefds);
}

long pass_dup(int oldfd) {
  return dup(oldfd);
}

long pass_getpid() {
  return getpid();
}

long pass_getuid() {
  return getuid();
}

long pass_getgid() {
  return getgid();
}

long pass_geteuid() {
  return geteuid();
}

long pass_getegid() {
  return getegid();
}

long pass_uname(struct utsname *buf) {
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
  return truncate(path, length);
}

long pass_ftruncate(int fd, off_t length) {
  return ftruncate(fd, length);
}

char *pass_getcwd(char *buf, size_t size) {
  return getcwd(buf, size);
}

long pass_mkdir(const char *pathname, mode_t mode) {
  return mkdir(pathname, mode);
}

long pass_unlink(const char *pathname) {
  return unlink(pathname);
}

long pass_readlink(const char *path, char *buf, size_t bufsiz) {
  return readlink(path, buf, bufsiz);
}

long pass_gettimeofday(struct timeval *tv, struct timezone *tz) {
  return gettimeofday(tv, tz);
}

long pass_getrusage(int who, struct rusage *usage) {
  return getrusage(who, usage);
}

long pass_gettid() {
  return syscall(__NR_gettid);
}

long pass_time(time_t *t) {
  return time(t);
}

long pass_futex(int *uaddr, int op, int val, const struct timespec *timeout,
    int *uaddr2, int val3) {
  return syscall(__NR_futex, uaddr, op, val, timeout, uaddr2, val3);
}

long pass_clock_gettime(clockid_t clk_id, struct timespec *tp) {
  return clock_gettime(clk_id, tp);
}

void pass_exit_group(int status) {
  exit(status);
}

long pass_tgkill(int tgid, int tid, int sig) {
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
  struct kvm_vcpu *vcpu = NULL;

  while((opt = getopt(argc, argv, "+dD")) != -1) {
    switch(opt) {
      case 'd':
        debug = 1;
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
	return 0;
}

