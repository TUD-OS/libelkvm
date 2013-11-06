#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <poll.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <libelf.h>

#include "kvm.h"
#include "pager.h"
#include "region.h"
#include "vcpu.h"
#include "list.h"
#include "elkvm-signal.h"

#define VM_MODE_X86    1
#define VM_MODE_PAGING 2
#define VM_MODE_X86_64 3

#define ELKVM_USER_CHUNK_OFFSET 1024*1024*1024

#ifdef _PREFIX_
#define RES_PATH _PREFIX_ "/share/libelkvm"
#endif

struct region_mapping {
  void *host_p;
  uint64_t guest_virt;
  size_t length;
  unsigned mapped_pages;
};

struct kvm_vm {
	int fd;
	struct vcpu_list *vcpus;
	struct kvm_pager pager;
	int run_struct_size;
	struct elkvm_memory_region_list *root_region;
	struct elkvm_handlers *syscall_handlers;
  list(struct region_mapping *, mappings);

	struct elkvm_memory_region *text;
  list(struct elkvm_memory_region *, heap);
	struct elkvm_memory_region *kernel_stack;
	struct elkvm_memory_region *gdt_region;
	struct elkvm_memory_region *idt_region;
  struct elkvm_memory_region *current_user_stack;

  struct elkvm_signals sigs;

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
	long (*mmap) (void *addr, size_t length, int prot, int flags, int fd,
      off_t offset, struct region_mapping *);
	long (*mprotect) (void *addr, size_t len, int prot);
	long (*munmap) (struct region_mapping *mapping);
  /* ... */
  long (*sigprocmask)(int how, const sigset_t *set, sigset_t *oldset);
  /* ... */
  long (*readv) (int fd, struct iovec *iov, int iovcnt);
  long (*writev) (int fd, struct iovec *iov, int iovcnt);
  long (*access) (const char *pathname, int mode);
  long (*dup) (int oldfd);
  /* ... */
  long (*nanosleep)(struct timespec *req, struct timespec *rem);
  long (*getpid)(void);
  /* ... */
  long (*getuid)(void);
  long (*getgid)(void);
  /* ... */
  long (*geteuid)(void);
  long (*getegid)(void);
	/* ... */
	long (*uname) (struct utsname *buf);
  long (*unlink) (const char *pathname);
  /* ... */
  long (*gettimeofday) (struct timeval *tv, struct timezone *tz);
  /* ... */
  long (*time) (time_t *t);
  /* ... */
  void (*exit_group) (int status);
};

/*
	Create a new VM, with the given mode, cpu count, memory and syscall handlers
	Return 0 on success, -1 on error
*/
int kvm_vm_create(struct elkvm_opts *, struct kvm_vm *, int, int, int,
		struct elkvm_handlers *);

/*
 * \brief Put the VM in debug mode
 */
int elkvm_set_debug(struct kvm_vm *);

/*
 * Setup the addresses of the system regions
 */
int elkvm_region_setup(struct kvm_vm *vm);

/*
	Load an ELF binary, given by the filename into the VM
*/
int kvm_vm_load_binary(struct kvm_vm *, const char *);

/*
	Writes the state of the VM to a given file descriptor
*/
void kvm_dump_vm(struct kvm_vm *, int);

/*
	Check if a given KVM capability exists, will return the result of the ioctl
*/
int kvm_check_cap(struct elkvm_opts *, int);

/*
	Returns the number of VCPUs in a VM
*/
int kvm_vm_vcpu_count(struct kvm_vm *);

/*
	Destroys a VM and all its data structures
*/
int kvm_vm_destroy(struct kvm_vm *);

/*
 * Maps a new mem chunk into the VM
*/
int kvm_vm_map_chunk(struct kvm_vm *, struct kvm_userspace_memory_region *);

/*
 * \brief Emulates (skips) the VMCALL instruction
 */
int elkvm_emulate_vmcall(struct kvm_vm *, struct kvm_vcpu *);

struct kvm_vcpu *elkvm_vcpu_get(struct kvm_vm *, int vcpu_id);
int elkvm_chunk_count(struct kvm_vm *);

struct kvm_userspace_memory_region elkvm_get_chunk(struct kvm_vm *, int chunk);

int elkvm_dump_valid_msrs(struct elkvm_opts *);

/*
 * Print the locations of the system memory regions
 */
void elkvm_print_regions(struct kvm_vm *);
void elkvm_dump_region(struct elkvm_memory_region *);

/**
 * \brief Enable VCPU debug mode
 */
int elkvm_debug_enable(struct kvm_vcpu *vcpu);

/**
 * \brief Set the VCPU in singlestepping mode
 */
int elkvm_debug_singlestep(struct kvm_vcpu *vcpu);

int elkvm_debug_breakpoint(struct kvm_vm *vm, struct kvm_vcpu *vcpu, uint64_t rip);

/*
 * Loads an ELF binary into the VM's system_chunk
*/
int elkvm_load_binary(struct kvm_vm *vm, const char *binary);

#ifdef __cplusplus
}
#endif
