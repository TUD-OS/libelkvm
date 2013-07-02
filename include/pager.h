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

/*
 * \brief Find the host pointer for a guest virtual address. Basically do a
 * page table walk.
*/
void *kvm_pager_get_host_p(struct kvm_pager *, uint64_t);

/*
 * \brief find the next pdpt, pd or pt
*/
uint64_t *kvm_pager_find_next_table(struct kvm_pager *, uint64_t, uint64_t *);

/*
 * \brief find an entry in a pml4, pdpt, pd or pt
 * Args: pager, host table base pointer, guest virtual address, offsets
*/
uint64_t *kvm_pager_find_table_entry(struct kvm_pager *, uint64_t *, uint64_t, 
		int, int);

/*
 * \brief Creates a new entry in a pml4, pdpt, pd or pt
 * Args: pager, entry, guest virtual address, offsets in guest virtual
*/
int kvm_pager_create_entry(struct kvm_pager *, uint64_t *, uint64_t, int, int);

/*
 * \brief Translate a host address into a guest physical address
*/
inline uint64_t host_to_guest_physical(struct kvm_pager *pager, void *host_p) {
	struct kvm_userspace_memory_region *region = 
		kvm_pager_find_region_for_host_p(pager, host_p);
	if(region == NULL) {
		return 0;
	}
	return (uint64_t)(host_p - region->userspace_addr + region->guest_phys_addr);
}

/*
 * \brief Check if an entry exists in a pml4, pdpt, pd or pt
*/
inline int entry_exists(uint64_t *e) {
	return *e & 0x1;
}

