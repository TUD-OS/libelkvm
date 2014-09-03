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

#include <vector>
#include <memory>

#include <types.h>
#include <heap.h>
#include <region_manager.h>


struct kvm_vcpu;

#define VM_MODE_X86    1
#define VM_MODE_PAGING 2
#define VM_MODE_X86_64 3

#define ELKVM_USER_CHUNK_OFFSET 1024*1024*1024

#ifdef _PREFIX_
#define RES_PATH _PREFIX_ "/share/libelkvm"
#endif

namespace Elkvm {

class VM;

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
  int (*bp_callback)(Elkvm::VM *vm);
};


struct elkvm_opts;

class VM {
  protected:
    std::vector<std::shared_ptr<struct kvm_vcpu>> cpus;

    /*
     * Debugging enabled in VM?
     */
    bool _debug;

    /*
     * TODO: This is the stuff that should be in a KVM-specific
     *       subclass if we ever decide to have alternative
     *       virtualization environments
     */
    struct {
      int fd;
      struct rlimit rlimits[RLIMIT_NLIMITS];
    } _vm;

    std::shared_ptr<RegionManager> _rm;
    HeapManager hm;

    int _vmfd;
    int _argc;
    char **_argv;
    char **_environ;
    int _run_struct_size;

    elkvm_signals sigs;
    elkvm_flat sighandler_cleanup;
    const Elkvm::elkvm_handlers *syscall_handlers;

  public:
    VM(int fd, int argc, char **argv, char **environ,
        int run_struct_size,
        const Elkvm::elkvm_handlers * const handlers,
        int debug);

    int add_cpu(int mode);

    bool address_mapped(guestptr_t addr) const;
    Mapping &find_mapping(guestptr_t addr);

    int load_flat(Elkvm::elkvm_flat &flat, const std::string path,
        bool kernel);

    std::shared_ptr<RegionManager> get_region_manager() { return _rm; }
    HeapManager &get_heap_manager() { return hm; }
    std::shared_ptr<struct kvm_vcpu> get_vcpu(int num) const;
    int get_vmfd() const { return _vmfd; }
    Elkvm::elkvm_flat &get_cleanup_flat();

    const Elkvm::elkvm_handlers * get_handlers() const
      { return syscall_handlers; }

    std::shared_ptr<struct sigaction> get_sig_ptr(unsigned sig) const;

    int debug_mode() const { return _debug; }

    /*
     * \brief Put the VM in debug mode
     */
    void set_debug(bool on = true) { _debug = on; }

    int set_entry_point(guestptr_t rip);

    /*
     * Initialize the VM's rlimits.
     * TODO: move to KVM subclass
     */
    void init_rlimits();
    
    /*
     * Dump the current stack frame for the vCPU.
     *
     * TODOL should be part of the VCPU class.
     */
    void dump_stack(struct kvm_vcpu *vcpu);
    

    /*
     * Dump guest memory at given address.
     */
    void dump_memory(guestptr_t ptr);
};

} // namespace Elkvm

/*
 * Create a new VM, with the given mode, cpu count, memory and syscall
 * handlers
 */
std::shared_ptr<Elkvm::VM>
elkvm_vm_create(Elkvm::elkvm_opts *,
    int mode,
    unsigned cpus,
    const Elkvm::elkvm_handlers * const,
    const char *binary,
    int debug);

/*
 * Runs all CPUS of the VM
 */
int elkvm_vm_run(std::shared_ptr<Elkvm::VM> vm);

/*
 * \brief Emulates (skips) the VMCALL instruction
 */
void elkvm_emulate_vmcall(struct kvm_vcpu *);

/*
 * \brief Deletes (frees) the chunk with number num and hands a new chunk
 *        with the newsize to a vm at the same memory slot.
 *        THIS WILL DELETE ALL DATA IN THE OLD CHUNK!
 */
int elkvm_chunk_remap(std::shared_ptr<Elkvm::VM> , int num, uint64_t newsize);

struct kvm_vcpu *elkvm_vcpu_get(std::shared_ptr<Elkvm::VM> , int vcpu_id);
uint64_t elkvm_chunk_count(std::shared_ptr<Elkvm::VM> );

struct kvm_userspace_memory_region elkvm_get_chunk(std::shared_ptr<Elkvm::VM> , int chunk);

int elkvm_dump_valid_msrs(struct elkvm_opts *);

/**
 * \brief Initialize the gdbstub and wait for gdb
 *        to connect
 */
void elkvm_gdbstub_init(std::shared_ptr<Elkvm::VM> vm);

/**
 * \brief Enable VCPU debug mode
 */
int elkvm_debug_enable(struct kvm_vcpu *vcpu);

