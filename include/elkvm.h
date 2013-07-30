#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <libelf.h>

#include "kvm.h"
#include "pager.h"
#include "region.h"

#define VM_MODE_X86    1
#define VM_MODE_PAGING 2
#define VM_MODE_X86_64 3

#define ELKVM_USER_CHUNK_OFFSET 1024*1024*1024

struct kvm_vm {
	int fd;
	struct vcpu_list *vcpus;
	struct kvm_pager pager;
	int run_struct_size;

	/*
	 * There will be 7 memory regions in the system_chunk:
	 * 1. text
	 * 2. data
	 * 3. bss (growing upward)
	 * 4. stack (growing downward)
	 * 5. env, which will hold the environtment strings
	 * 6. idt, which will hold the interrupt descriptor table
	 * 7. pt, which will hold the page tables
	 */
	struct elkvm_memory_region region[7];
};

/*
	Create a new VM, with the given mode, cpu count and memory
	Return 0 on success, -1 on error
*/
int kvm_vm_create(struct elkvm_opts *, struct kvm_vm *, int, int, int);

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
 * Print the locations of the system memory regions
 */
void elkvm_print_regions(struct elkvm_memory_region *);

#ifdef __cplusplus
}
#endif
