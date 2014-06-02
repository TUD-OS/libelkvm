#pragma once

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "list.h"

#include <elkvm.h>

#define PAGER_MODE_X86     1
#define PAGER_MODE_X86_E   2
#define PAGER_MODE_X86_64  3

#define ELKVM_PAGER_MEMSIZE 16*1024*1024
#define ELKVM_SYSTEM_MEMSIZE 16*1024*1024
#define ELKVM_SYSTEM_MEMGROW 256*1024*1024
#define KERNEL_SPACE_BOTTOM 0xFFFF800000000000
#define ADDRESS_SPACE_TOP 0xFFFFFFFFFFFFFFFF

#define PT_BIT_PRESENT     0x1
#define PT_BIT_WRITEABLE   0x2
#define PT_BIT_USER        0x4
#define PT_BIT_WRITE_CACHE 0x8
#define PT_BIT_NO_CACHE    0x16
#define PT_BIT_USED        0x32
#define PT_BIT_LARGEPAGE   (1L << 7)
#define PT_BIT_NXE         (1L << 63)

#define HOST_PAGESIZE        0x1000
#define ELKVM_PAGESIZE       0x1000
#define ELKVM_PAGESIZE_LARGE 0x200000
#define ELKVM_PAGESIZE_HUGE  0x100000000
/*
 * KVM allows only for 32 memory slots in Linux 3.8
 * and 128 slots on Linux 3.11
 * its down to 125 slots in Linux 3.13
 */
#define KVM_MEMORY_SLOTS 125

typedef unsigned int ptopt_t;
#define PT_OPT_WRITE 0x1
#define PT_OPT_EXEC  0x2
#define PT_OPT_LARGE 0x4
#define PT_OPT_HUGE  0x8

struct kvm_vm;

struct kvm_pager {
	uint64_t guest_top_pm;
	int mode;
	struct kvm_vm *vm;
	struct kvm_userspace_memory_region system_chunk;
  list(struct kvm_userspace_memory_region *, other_chunks);
	void *host_pml4_p;
	void *host_next_free_tbl_p;
	uint64_t guest_next_free;
  uint64_t brk_addr;
  uint64_t total_memsz;
  uint32_t free_slot[KVM_MEMORY_SLOTS];
  int free_slot_id;
};

/*
	Initialize the Pager with the given mode
*/
int elkvm_pager_initialize(struct kvm_vm *, int);

struct kvm_userspace_memory_region *
elkvm_pager_alloc_chunk(struct kvm_pager *pager, void *addr,
    uint64_t chunk_size, int flags);
/*
	Let Pager create a mem chunk of the given size. The mem_chunk will be added
  to the end of the other_chunks list
*/
int elkvm_pager_create_mem_chunk(struct kvm_pager *, void **, int);

/*
	Create Page Tables according to given mode
*/
int elkvm_pager_create_page_tables(struct kvm_pager *, int);

/*
 * Maps a new mem chunk into the VM
*/
int elkvm_pager_map_chunk(struct kvm_vm *, struct kvm_userspace_memory_region *);

/*
 * Append a kvm_userspace_memory_region to the end of the list of memory regions
*/
int elkvm_pager_append_mem_chunk(struct kvm_pager *, struct kvm_userspace_memory_region *);

int elkvm_pager_chunk_count(struct kvm_pager *pager);

int elkvm_pager_free_chunk(struct kvm_pager *pager,
    struct kvm_userspace_memory_region *chunk);

struct kvm_userspace_memory_region elkvm_pager_get_system_chunk(
    struct kvm_pager *);
struct kvm_userspace_memory_region *elkvm_pager_get_chunk(struct kvm_pager *, int);

/*
 * \brief Create a Mapping in Kernel Space
 * params are pager, host virtual address, writeable and executable bit
 */
uint64_t elkvm_pager_map_kernel_page(struct kvm_pager *, void *,int, int);

int elkvm_pager_unmap_region(struct kvm_pager *pager, uint64_t guest_start_addr,
    unsigned pages);
int elkvm_pager_map_region(struct kvm_pager *pager, void *host_start_p,
    uint64_t guest_start_addr, unsigned pages, ptopt_t opts);

/*
 * \brief Create a Mapping in the Page Tables for a physical address
 * params are pager, host virtual address, guest_virtual address, writeable
 * and executable bit
*/
int elkvm_pager_create_mapping(struct kvm_pager *, void *host_mem_p,
    uint64_t guest_virtual, ptopt_t opts);

/*
 * \brief Destroy a Mapping in the Page tables
 */
int elkvm_pager_destroy_mapping(struct kvm_pager *pager, uint64_t guest_virtual);

/*
 * \brief Find the memory region for a host address
*/
struct kvm_userspace_memory_region *
	elkvm_pager_find_region_for_host_p(struct kvm_pager *, void *);

/*
 * \brief walk the page table to find a pt_entry
 * params are pager, guest virtual address, writeable, executable bits
 * and a create flag
 */
uint64_t *elkvm_pager_page_table_walk(struct kvm_pager *, uint64_t guest_virtual,
    ptopt_t opts, int);

/*
 * \brief Find the host pointer for a guest virtual address. Basically do a
 * page table walk.
*/
void *elkvm_pager_get_host_p(struct kvm_pager *, uint64_t);

/*
 * \brief find the HOST ADDRESS of the next pdpt, pd or pt
*/
uint64_t *elkvm_pager_find_next_table(struct kvm_pager *, uint64_t *);

/*
 * \brief find an entry in a pml4, pdpt, pd or pt
 * Args: pager, host table base pointer, guest virtual address, offsets
*/
uint64_t *elkvm_pager_find_table_entry(uint64_t *, guestptr_t,
		int, int);

/*
 * \brief Creates a new table and puts the entry in a pml4, pdpt, pd or pt
 * Args: pager, entry, writeable, executable
*/
int elkvm_pager_create_table(struct kvm_pager *, uint64_t *, ptopt_t opts);

/*
 * \brief Creates a new entry in a pml4, pdpt, pd or pt
 * params are pager, host virtual address, guest physical address,
 * writeable and executable bits
 */
void elkvm_pager_create_entry(uint64_t *host_entry_p, guestptr_t guest_next,
    ptopt_t opts);

int elkvm_pager_set_brk(struct kvm_pager *, uint64_t);
int elkvm_pager_handle_pagefault(struct kvm_pager *, uint64_t, uint32_t);

void elkvm_pager_dump_page_fault_info(guestptr_t pfla,
    uint32_t err_code, void *host_p);
void elkvm_pager_dump_page_tables(struct kvm_pager *);
void elkvm_pager_dump_table(struct kvm_pager *, void *, int);

uint64_t host_to_guest_physical(struct kvm_pager *pager, void *host_p);
bool address_in_region(struct kvm_userspace_memory_region *r, void *host_addr);
bool guest_address_in_region(struct kvm_userspace_memory_region *r,
    uint64_t guest_physical);
bool entry_exists(uint64_t *e);
guestptr_t page_begin(guestptr_t addr);
bool page_aligned(guestptr_t addr);
guestptr_t next_page(guestptr_t addr);
int pages_from_size(uint64_t size);
int page_remain(guestptr_t addr);
unsigned int offset_in_page(guestptr_t addr);
uint64_t pagesize_align(uint64_t size);
