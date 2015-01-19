#pragma once

#include <poll.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/socket.h>
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

#include <elkvm/elkvm-log.h>
#include <elkvm/types.h>
#include <elkvm/heap.h>
#include <elkvm/region_manager.h>
#include <elkvm/syscall.h>

#define VM_MODE_X86    1
#define VM_MODE_PAGING 2
#define VM_MODE_X86_64 3

#define ELKVM_USER_CHUNK_OFFSET 1024*1024*1024

#ifdef _PREFIX_
#define RES_PATH _PREFIX_ "/share/libelkvm"
#endif

namespace Elkvm {

class ElfBinary;
class VCPU;
class VM;

/*
 * Functions to be called upon a hypercall from a VM.
 *
 * pre_handler() is called before ELKVM does any processing
 *               of the event.
 * post_handler() is called after ELKVM's event processing,
 *               but BEFORE signals are potentially delivered to the VM.
 *
 * ELVKM provides a default implementation (Elkvm::hypercall_null) that
 * performs no interception at all.
 */
struct hypercall_handlers {
    long (*pre_handler) (Elkvm::VM* vm,
                         const std::shared_ptr<VCPU>& vcpu,
                         int eventtype);
    long (*post_handler) (Elkvm::VM* vm,
                          const std::shared_ptr<VCPU>& vcpu,
                          int eventtype);
};

/*
 * Functions that implement system calls. A monitor can overwrite
 * one or more of these pointers in order to implement its own version
 * of a system call. ELKVM provides a default implementation
 * (Elkvm::default_handlers) that will simply redirect every system call to
 * the underlying host kernel.
 */
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
  long (*ioctl) (int fd, unsigned long request, char *argp);
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
  long (*socket)(int, int, int);
  long (*accept)(int, struct sockaddr*, socklen_t*);
  long (*bind)(int, const struct sockaddr*, socklen_t);
  long (*listen)(int, int);
  long (*getsockname)(int, struct sockaddr*, socklen_t*);
  long (*setsockopt)(int, int, int, const void*, socklen_t);
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
  int (*chdir)(char const*);
  int (*fchdir)(int);
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
  long (*epoll_create)(int);
  long (*epoll_ctl)(int, int, int, struct epoll_event*);
  long (*epoll_wait)(int, struct epoll_event*, int, int);
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

/*
 * Default set of system call handlers that simply redirects system calls to
 * the kernel according to the unpacked parameters.
 */
extern struct elkvm_handlers default_handlers;
/*
 * Default set of hypercall handlers that performs no hypercall intercaption.
 */
extern struct hypercall_handlers hypercall_null;

struct elkvm_opts;

class VM {
  protected:
    std::vector<std::shared_ptr<VCPU>> cpus;

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
    std::shared_ptr<Elkvm::Region> _gdt;
    HeapManager hm;

    int _vmfd;
    int _argc;
    char **_argv;
    char **_environ;
    int _run_struct_size;

    elkvm_signals sigs;
    elkvm_flat sighandler_cleanup;
    const Elkvm::hypercall_handlers *hypercall_handlers;
    const Elkvm::elkvm_handlers *syscall_handlers;

  public:
    VM(int fd, int argc, char **argv, char **environ,
        int run_struct_size,
        const Elkvm::hypercall_handlers * const hyp_handlers,
        const Elkvm::elkvm_handlers * const handlers,
        int debug);

    VM(VM const&) = delete;
    VM& operator=(VM const&) = delete;

    int add_cpu();

    bool address_mapped(guestptr_t addr) const;
    Mapping &find_mapping(guestptr_t addr);

    int load_flat(Elkvm::elkvm_flat &flat, const std::string path,
        bool kernel);

    void unpack_syscall(CURRENT_ABI::paramtype *arg);
    void unpack_syscall(CURRENT_ABI::paramtype *arg1,
        CURRENT_ABI::paramtype *arg2);
    void unpack_syscall(CURRENT_ABI::paramtype *arg1,
        CURRENT_ABI::paramtype *arg2,
        CURRENT_ABI::paramtype *arg3);
    void unpack_syscall(CURRENT_ABI::paramtype *arg1,
        CURRENT_ABI::paramtype *arg2,
        CURRENT_ABI::paramtype *arg3,
        CURRENT_ABI::paramtype *arg4);
    void unpack_syscall(CURRENT_ABI::paramtype *arg1,
        CURRENT_ABI::paramtype *arg2,
        CURRENT_ABI::paramtype *arg3,
        CURRENT_ABI::paramtype *arg4,
        CURRENT_ABI::paramtype *arg5);
    void unpack_syscall(CURRENT_ABI::paramtype *arg1,
        CURRENT_ABI::paramtype *arg2,
        CURRENT_ABI::paramtype *arg3,
        CURRENT_ABI::paramtype *arg4,
        CURRENT_ABI::paramtype *arg5,
        CURRENT_ABI::paramtype *arg6);

    const std::shared_ptr<RegionManager>& get_region_manager() const { return _rm; }
    HeapManager &get_heap_manager() { return hm; }
    const std::shared_ptr<VCPU>& get_vcpu(int num) const;
    int get_vmfd() const { return _vmfd; }
    Elkvm::elkvm_flat &get_cleanup_flat();

    const std::shared_ptr<Elkvm::Region>& get_gdt_region() { return _gdt; }
    void set_gdt_region(std::shared_ptr<Elkvm::Region> gdt) { _gdt = gdt; }

    const Elkvm::elkvm_handlers * get_handlers() const
    {
        //INFO() << "handlers @ " << (void*)this->syscall_handlers;
        return this->syscall_handlers;
    }

    const Elkvm::hypercall_handlers* get_hyp_handlers() const
    { return this->hypercall_handlers; }

    const struct sigaction* get_sig_ptr(unsigned sig) const;

    int debug_mode() const { return _debug; }

    /*
     * \brief Put the VM in debug mode
     */
    void set_debug(bool on = true) { _debug = on; }

    /*
     * Initialize the VM's rlimits.
     * TODO: move to KVM subclass
     */
    int init_rlimits();



    /*
     * Runs all CPUS of the VM
     */
    int run();

    /*
     * Handle VM events
     */
    int handle_syscall(const std::shared_ptr<VCPU>&);
    int handle_interrupt(const std::shared_ptr<VCPU>&);
    int handle_hypercall(const std::shared_ptr<VCPU>&);

    /*
     * Signal management
     */
    int signal_deliver();
    int signal_register(int signum,
                        struct sigaction *act,
                        struct sigaction *oldact);

    /*
     * Memory stuff
     */
    uint64_t chunk_count()
    { return get_region_manager()->get_pager().chunk_count(); }

    /*
     * \brief Deletes (frees) the chunk with number num and hands a new chunk
     *        with the newsize to a vm at the same memory slot.
     *        THIS WILL DELETE ALL DATA IN THE OLD CHUNK!
     */
    int chunk_remap(int num, size_t newsize);

    struct kvm_userspace_memory_region get_chunk(int chunk)
    { return *get_region_manager()->get_pager().get_chunk(chunk); }

};

std::shared_ptr<VM> create_virtual_hardware(const elkvm_opts * const opts,
        const Elkvm::hypercall_handlers * const hyp,
        const Elkvm::elkvm_handlers * const handlers,
        unsigned cpus,
        int mode);
int load_elf_binary(const std::shared_ptr<VM> vm,
        elkvm_opts * opts,
        const std::string binary);
int setup_proxy_os(const std::shared_ptr<VM> vm);

std::shared_ptr<VM> create_vm_object(const elkvm_opts * const opts,
    const hypercall_handlers * const hyp,
    const elkvm_handlers * const handlers);
int create_vcpus(const std::shared_ptr<VM> vm, unsigned cpus);
int create_and_setup_environment(const ElfBinary &bin,
    const std::shared_ptr<VM> vm,
    elkvm_opts * opts,
    const std::shared_ptr<VCPU> vcpu);

int create_idt(const std::shared_ptr<VM> vm,
    const std::shared_ptr<VCPU> vcpu);
int create_sysenter(const std::shared_ptr<VM> vm,
    const std::shared_ptr<VCPU> vcpu);
int create_sighandler(const std::shared_ptr<VM> vm);

std::ostream &print_code(std::ostream &os, const VM &vm, const VCPU &vcpu);
std::ostream &print_code(std::ostream &os, const VM &vm, guestptr_t addr);

} // namespace Elkvm

/*
 * Create a new VM, with the given mode, cpu count, memory and syscall
 * handlers
 */
std::shared_ptr<Elkvm::VM>
elkvm_vm_create(Elkvm::elkvm_opts *,
                const char *binary,
                unsigned cpus = 1,
                const Elkvm::hypercall_handlers * const = &Elkvm::hypercall_null,
                const Elkvm::elkvm_handlers * const = &Elkvm::default_handlers,
                int mode = VM_MODE_X86_64,
                bool debug = false);


/*
 * Create a new VM without loading an application binary.
 */
std::shared_ptr<Elkvm::VM>
elkvm_vm_create_raw(Elkvm::elkvm_opts *,
                    unsigned cpus = 1,
                    const Elkvm::hypercall_handlers * const = &Elkvm::hypercall_null,
                    const Elkvm::elkvm_handlers * const = &Elkvm::default_handlers,
                    int mode = VM_MODE_X86_64,
                    bool debug = false);


/*
 * \brief Emulates (skips) the VMCALL instruction
 */
void elkvm_emulate_vmcall(std::shared_ptr<Elkvm::VCPU> );
int elkvm_dump_valid_msrs(struct elkvm_opts *);

/**
 * \brief Initialize the gdbstub and wait for gdb
 *        to connect
 */
void elkvm_gdbstub_init(std::shared_ptr<Elkvm::VM> vm);

/**
 * \brief Enable VCPU debug mode
 */
int elkvm_debug_enable(std::shared_ptr<Elkvm::VCPU> vcpu);

