#include <cstdio>
#include <errno.h>
#include <cstring>
#include <signal.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>

#include <elkvm/elkvm.h>
#include <elkvm/kvm.h>
#include <elkvm/vcpu.h>
#include <elkvm/stack.h>

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

long pass_lseek(int fd, off_t offset, int whence) {
  return lseek(fd, offset, whence);
}

long pass_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset,
    struct region_mapping *mapping) {
  void *host_p = mmap(addr, length, prot, flags, fd, offset);
  mapping->host_p = host_p;
  mapping->guest_virt = (uint64_t)host_p;
  mapping->length = length;
  return errno;
}

long pass_munmap(struct region_mapping *mapping) {
  return munmap(mapping->host_p, mapping->length);
}

long pass_sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
  return sigprocmask(how, set, oldset);
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

long pass_dup(int oldfd) {
  return dup(oldfd);
}

long pass_nanosleep(struct timespec *req, struct timespec *rem) {
  return nanosleep(req, rem);
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

long pass_unlink(const char *pathname) {
  return unlink(pathname);
}

long pass_gettimeofday(struct timeval *tv, struct timezone *tz) {
  return gettimeofday(tv, tz);
}

long pass_time(time_t *t) {
  return time(t);
}

void pass_exit_group(int status) {
}

struct elkvm_handlers example_handlers = {
	.read = pass_read,
	.write = pass_write,
	.open = pass_open,
	.close = pass_close,
	.stat = pass_stat,
	.fstat = pass_fstat,
	.lstat = NULL,
	.poll = NULL,
	.lseek = pass_lseek,
	.mmap = pass_mmap,
  .mprotect = NULL,
  .munmap = pass_munmap,
  /* ... */
  .sigprocmask = pass_sigprocmask,
  /* ... */
  .readv = pass_readv,
  .writev = pass_writev,
  .access = pass_access,
  .dup = pass_dup,
  .nanosleep = pass_nanosleep,
  /* ... */
  .getpid = pass_getpid,
  /* ... */
  .getuid  = pass_getuid,
  .getgid  = pass_getgid,
  .geteuid = pass_geteuid,
  .getegid = pass_getegid,
	/* ... */
	.uname = pass_uname,
  .unlink = pass_unlink,
  /* ... */
  .gettimeofday = pass_gettimeofday,
  /* ... */
  .time = pass_time,
  /* ... */
  .exit_group = pass_exit_group,
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
  int singlestep = 0;
  int myopts = 1;
  opterr = 0;
  struct kvm_vcpu *vcpu = NULL;

  while((opt = getopt(argc, argv, "+drs")) != -1) {
    switch(opt) {
      case 'd':
        debug = 1;
        myopts++;
        break;
      case 's':
        singlestep = 1;
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

	err = elkvm_vm_create(&elkvm, &vm, VM_MODE_X86_64, 1, 1024*1024, &example_handlers);
	if(err) {
		printf("ERROR creating VM errno: %i Msg: %s\n", -err, strerror(-err));
		return -1;
	}

//  printf("LOADING binary %s with %i opts\n", binary, binargc);
//  for(int i = 0; i < binargc; i++) {
//    printf("binargv[%i] %s\n", i, binargv[i]);
//  }

	err = elkvm_load_binary(&vm, binary);
	if(err) {
		printf("ERROR loading binary %s\n", binary);
    printf("Errno %i Msg: %s\n", -err, strerror(-err));
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

  if(singlestep) {
    err = elkvm_debug_singlestep(vcpu);
    printf("err: %i errno: %i\n", err, errno);
  	if(err) {
  		printf("ERROR putting VCPU into debug mode errno: %i Msg: %s\n", -err, strerror(errno));
  		return -1;
  	}
  }

  struct timeval begin;
  struct timeval end;
  err = gettimeofday(&begin, NULL);
  assert(err == 0);

	err = kvm_vcpu_loop(vcpu);
	if(err) {
		printf("ERROR running VCPU errno: %i Msg: %s\n", -err, strerror(-err));
		return -1;
	}
  err = gettimeofday(&end, NULL);
  assert(err == 0);

  time_t      run_secs  = end.tv_sec  - begin.tv_sec;
  suseconds_t run_usecs = end.tv_usec - begin.tv_usec;

  printf("=========================================\n");
  printf("|                                       |\n");
  printf("| TIMEKEEPER, results for               |\n");
  printf("| %s |\n", binary);
  printf("| %5lu s %4lu usec             |\n", run_secs, run_usecs);
  printf("=========================================\n");

	err = elkvm_cleanup(&elkvm);
	if(err) {
		printf("ERROR cleaning up errno: %i Msg: %s\n", -err, strerror(-err));
		return -1;
	}

	return 0;
}

