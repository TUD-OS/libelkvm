#pragma once

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>

#define PAGER_MODE_X86     1
#define PAGER_MODE_X86_E   2
#define PAGER_MODE_X86_64  3

#define ELKVM_SYSTEM_MEMSIZE 16*1024*1024
#define ELKVM_SYSTEM_MEMGROW 8*1024*1024
#define KERNEL_SPACE_BOTTOM 0xFFFF800000000000
#define ADDRESS_SPACE_TOP 0xFFFFFFFFFFFFFFFF

#define PT_BIT_PRESENT     0x1
#define PT_BIT_WRITEABLE   0x2
#define PT_BIT_USER        0x4
#define PT_BIT_WRITE_CACHE 0x8
#define PT_BIT_NO_CACHE    0x16
#define PT_BIT_USED        0x32
#define PT_BIT_NXE         (1L << 63)

#define ELKVM_EXEC         (1 << 0)
#define ELKVM_WRITE        (1 << 1)

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
	uint64_t guest_next_free;
  uint64_t brk_addr;
  uint64_t total_memsz;
};

/*
	Initialize the Pager with the given mode
*/
int kvm_pager_initialize(struct kvm_vm *, int);

struct kvm_userspace_memory_region *
kvm_pager_alloc_chunk(struct kvm_pager *pager, void *addr,
    uint64_t chunk_size, int flags);
/*
	Let Pager create a mem chunk of the given size. The mem_chunk will be added
  to the end of the other_chunks list
*/
int kvm_pager_create_mem_chunk(struct kvm_pager *, void **, int);

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

int elkvm_pager_chunk_count(struct kvm_pager *pager, struct chunk_list **current);

struct kvm_userspace_memory_region elkvm_pager_get_system_chunk(
    struct kvm_pager *);
struct kvm_userspace_memory_region *elkvm_pager_get_chunk(struct kvm_pager *, int);

/*
 * \brief Create a Mapping in Kernel Space
 * params are pager, host virtual address, writeable and executable bit
 */
uint64_t kvm_pager_map_kernel_page(struct kvm_pager *, void *,int, int);

int kvm_pager_map_region(struct kvm_pager *pager, void *host_start_p,
    uint64_t guest_start_addr, int pages, int access);

/*
 * \brief Create a Mapping in the Page Tables for a physical address
 * params are pager, host virtual address, guest_virtual address, writeable
 * and executable bit
*/
int kvm_pager_create_mapping(struct kvm_pager *, void *, uint64_t, int, int);

/*
 * \brief Destroy a Mapping in the Page tables
 */
int kvm_pager_destroy_mapping(struct kvm_pager *pager, uint64_t guest_virtual);

/*
 * \brief Find the memory region for a host address
*/
struct kvm_userspace_memory_region *
	kvm_pager_find_region_for_host_p(struct kvm_pager *, void *);

/*
 * \brief walk the page table to find a pt_entry
 * params are pager, guest virtual address, writeable, executable bits
 * and a create flag
 */
uint64_t *kvm_pager_page_table_walk(struct kvm_pager *, uint64_t, int, int, int);

/*
 * \brief Find the host pointer for a guest virtual address. Basically do a
 * page table walk.
*/
void *kvm_pager_get_host_p(struct kvm_pager *, uint64_t);

/*
 * \brief find the HOST ADDRESS of the next pdpt, pd or pt
*/
uint64_t *kvm_pager_find_next_table(struct kvm_pager *, uint64_t *);

/*
 * \brief find an entry in a pml4, pdpt, pd or pt
 * Args: pager, host table base pointer, guest virtual address, offsets
*/
uint64_t *kvm_pager_find_table_entry(struct kvm_pager *, uint64_t *, uint64_t,
		int, int);

/*
 * \brief Creates a new table and puts the entry in a pml4, pdpt, pd or pt
 * Args: pager, entry, writeable, executable
*/
int kvm_pager_create_table(struct kvm_pager *, uint64_t *, int, int);

/*
 * \brief Creates a new entry in a pml4, pdpt, pd or pt
 * params are pager, host virtual address, guest physical address,
 * writeable and executable bits
 */
int kvm_pager_create_entry(struct kvm_pager *, uint64_t *, uint64_t, int, int);

int kvm_pager_set_brk(struct kvm_pager *, uint64_t);
int kvm_pager_handle_pagefault(struct kvm_pager *, uint64_t, uint32_t);

void kvm_pager_dump_page_fault_info(struct kvm_pager *, uint64_t pfla,
    uint32_t err_code, void *host_p);
void kvm_pager_dump_page_tables(struct kvm_pager *);
void kvm_pager_dump_table(struct kvm_pager *, void *, int);

/*
 * \brief Translate a host address into a guest physical address
*/
static inline uint64_t host_to_guest_physical(struct kvm_pager *pager, void *host_p) {
	struct kvm_userspace_memory_region *region =
		kvm_pager_find_region_for_host_p(pager, host_p);
	if(region == NULL) {
		return 0;
	}
	assert(region->userspace_addr <= (uint64_t)host_p);
	return (uint64_t)(host_p - region->userspace_addr + region->guest_phys_addr);
}

static inline int address_in_region(struct kvm_userspace_memory_region *r,
    void *host_addr) {
  return ((void *)r->userspace_addr <= host_addr) &&
      (host_addr < ((void *)r->userspace_addr + r->memory_size));
}

static inline int guest_address_in_region(struct kvm_userspace_memory_region *r,
    uint64_t guest_physical) {
  return (r->guest_phys_addr <= guest_physical) &&
      (guest_physical < (r->guest_phys_addr + r->memory_size));
}

/*
 * \brief Check if an entry exists in a pml4, pdpt, pd or pt
*/
static inline int entry_exists(uint64_t *e) {
	return *e & 0x1;
}

static uint64_t page_begin(uint64_t addr) {
  return (addr & ~0xFFF);
}

static uint64_t next_page(uint64_t addr) {
  return (addr & ~0xFFF) + 0x1000;
}

static int pages_from_size(uint64_t size) {
  if(size % 1000) {
    return (size / 0x1000) + 1;
  } else {
    return size / 0x1000;
  }
}

static int offset_in_page(uint64_t addr) {
  return addr & 0xFFF;
}

