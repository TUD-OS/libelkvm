#pragma once

#include <poll.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <libelf.h>
#include <linux/kvm.h>

typedef uint64_t guestptr_t;

struct linux_dirent {
    unsigned long  d_ino;     /* Inode number */
    unsigned long  d_off;     /* Offset to next linux_dirent */
    unsigned short d_reclen;  /* Length of this linux_dirent */
    char           d_name[];  /* Filename (null-terminated) */
                      /* length is actually (d_reclen - 2 -
                         offsetof(struct linux_dirent, d_name)) */
    /*
    char           pad;       // Zero padding byte
    char           d_type;    // File type (only since Linux
                              // 2.6.4); offset is (d_reclen - 1)
    */
};

#include "pager-c.h"
#include "region-c.h"
#include "vcpu.h"
#include "elkvm-signal.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VM_MODE_X86    1
#define VM_MODE_PAGING 2
#define VM_MODE_X86_64 3

#define ELKVM_USER_CHUNK_OFFSET 1024*1024*1024

#ifdef _PREFIX_
#define RES_PATH _PREFIX_ "/share/libelkvm"
#endif

struct elkvm_opts;

struct region_mapping {
  void *host_p;
  guestptr_t guest_virt;
  size_t length;
  unsigned mapped_pages;
  int prot;
  int flags;
  int fd;
  off_t offset;
};

struct kvm_vm {
	int fd;
	const struct elkvm_handlers *syscall_handlers;

	struct elkvm_memory_region *gdt_region;
	struct elkvm_memory_region *idt_region;

  struct elkvm_signals sigs;
  struct elkvm_flat *sighandler_cleanup;
  struct rlimit rlimits[RLIMIT_NLIMITS];

  int debug;
};

struct elkvm_handlers {
	long (*read) (int fd, void *buf, size_t count);
	long (*write) (int fd, void *buf, size_t count);
	long (*open) (const char *pathname, int flags, mode_t mode);
	long (*close) (int fd);
	long (*stat) (const char *path, struct stat *buf);
	long (*fstat) (int fd, struct stat *buf);
	long (*lstat) (const char *path, struct stat *buf);
	long (*poll) (struct pollfd *fds, nfds_t nfds, int timeout);
	long (*lseek) (int fd, off_t offset, int whence);
  /* TODO mmap should be well documented! */
  long (*mmap_before) (struct region_mapping *);
  long (*mmap_after) (struct region_mapping *);
	long (*mprotect) (void *addr, size_t len, int prot);
	long (*munmap) (struct region_mapping *mapping);
  /* ... */
  long (*sigaction) (int signum, const struct sigaction *act,
      struct sigaction *oldact);
  long (*sigprocmask)(int how, const sigset_t *set, sigset_t *oldset);
  /* ... */
  long (*readv) (int fd, struct iovec *iov, int iovcnt);
  long (*writev) (int fd, struct iovec *iov, int iovcnt);
  long (*access) (const char *pathname, int mode);
  long (*pipe) (int pipefd[2]);
  long (*dup) (int oldfd);
  /* ... */
  long (*nanosleep)(const struct timespec *req, struct timespec *rem);
  long (*getpid)(void);
  /* ... */
  long (*getuid)(void);
  long (*getgid)(void);
  /* ... */
  long (*geteuid)(void);
  long (*getegid)(void);
	/* ... */
	long (*uname) (struct utsname *buf);
  long (*fcntl) (int fd, int cmd, ...);
  long (*truncate) (const char *path, off_t length);
  long (*ftruncate) (int fd, off_t length);
  int (*getdents) (unsigned fd, struct linux_dirent *dirp, unsigned count);
  char *(*getcwd) (char *buf, size_t size);
  long (*mkdir) (const char *pathname, mode_t mode);
  long (*unlink) (const char *pathname);
  long (*readlink) (const char *path, char *buf, size_t bufsiz);
  /* ... */
  long (*gettimeofday) (struct timeval *tv, struct timezone *tz);
  long (*getrusage) (int who, struct rusage *usage);
  /* ... */
  long (*times) (struct tms *buf);
  /* ... */
  long (*statfs) (const char *path, struct statfs *buf);
  /* ... */
  long (*gettid)(void);
  /* ... */
  long (*time) (time_t *t);
  long (*futex)(int *uaddr, int op, int val, const struct timespec *timeout,
      int *uaddr2, int val3);
  /* ... */
  long (*clock_gettime) (clockid_t clk_id, struct timespec *tp);
  void (*exit_group) (int status);
  long (*tgkill)(int tgid, int tid, int sig);

  int (*openat) (int dirfd, const char *pathname, int flags);

  /* ELKVM debug callbacks */

  /*
   * called after a breakpoint has been hit, should return 1 to abort the program
   * 0 otherwise, if this is set to NULL elkvm will execute a simple debug shell
   */
  int (*bp_callback)(struct kvm_vm *vm);

};

/*
	Create a new VM, with the given mode, cpu count, memory and syscall handlers
	Return 0 on success, -1 on error
*/
int elkvm_vm_create(struct elkvm_opts *, struct kvm_vm *, int mode, unsigned cpus,
		const struct elkvm_handlers *, const char *binary);

/*
 * Runs all CPUS of the VM
 */
int elkvm_vm_run(struct kvm_vm *vm);

/*
 * \brief Put the VM in debug mode
 */
int elkvm_set_debug(struct kvm_vm *);

/*
 * \brief Emulates (skips) the VMCALL instruction
 */
void elkvm_emulate_vmcall(struct kvm_vcpu *);

/*
 * \brief Deletes (frees) the chunk with number num and hands a new chunk
 *        with the newsize to a vm at the same memory slot.
 *        THIS WILL DELETE ALL DATA IN THE OLD CHUNK!
 */
int elkvm_chunk_remap(struct kvm_vm *, int num, uint64_t newsize);

struct kvm_vcpu *elkvm_vcpu_get(struct kvm_vm *, int vcpu_id);
uint64_t elkvm_chunk_count(struct kvm_vm *);

struct kvm_userspace_memory_region elkvm_get_chunk(struct kvm_vm *, int chunk);

int elkvm_dump_valid_msrs(struct elkvm_opts *);

/**
 * \brief Initialize the gdbstub and wait for gdb
 *        to connect
 */
void elkvm_gdbstub_init(struct kvm_vm *vm);

/**
 * \brief Enable VCPU debug mode
 */
int elkvm_debug_enable(struct kvm_vcpu *vcpu);

#ifdef __cplusplus
}
#endif
