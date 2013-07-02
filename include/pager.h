#pragma once

#include <inttypes.h>
#include <stdint.h>

#define PAGER_MODE_X86     1
#define PAGER_MODE_X86_E   2
#define PAGER_MODE_X86_64  3

#define ELKVM_SYSTEM_MEMSIZE 16*1024*1024

struct kvm_vm;

struct chunk_list {
	struct chunk_list *next;
	struct kvm_userspace_memory_region *chunk;
};

struct kvm_pager {
	uint64_t guest_top_pm;
	int mode;
	struct kvm_vm *vm;
	struct kvm_userspace_memory_region system_chunk;
	struct chunk_list *other_chunks;
	void *host_pml4_p;
	void *host_next_free_tbl_p;
};

/*
	Initialize the Pager with the given mode
*/
int kvm_pager_initialize(struct kvm_vm *, int);

/*
	Let Pager create a mem chunk of the given size, attach it to the given guest_base. The mem_chunk will be added to the end of the other_chunks list
*/
int kvm_pager_create_mem_chunk(struct kvm_pager *, int, uint64_t);

/*
	Create Page Tables according to given mode
*/
int kvm_pager_create_page_tables(struct kvm_pager *, int);

/*
	Check if the given base address already exists in the guest
*/
int kvm_pager_is_invalid_guest_base(struct kvm_pager *, uint64_t);

/*
 * Append a kvm_userspace_memory_region to the end of the list of memory regions
*/
int kvm_pager_append_mem_chunk(struct kvm_pager *, struct kvm_userspace_memory_region *);

/*
 * \brief Create a Mapping in the Page Tables for a physical address
*/
int kvm_pager_create_mapping(struct kvm_pager *, void *host_mem_p, uint64_t guest_virtual);

/*
 * \brief Find the memory region for a host address
*/
struct kvm_userspace_memory_region *
	kvm_pager_find_region_for_host_p(struct kvm_pager *, void *);

