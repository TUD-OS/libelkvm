#pragma once

#include <inttypes.h>
#include <stdint.h>

#include <mem_chunk.h>

#define PAGER_MODE_X86     1
#define PAGER_MODE_X86_E   2
#define PAGER_MODE_X86_64  3

#define ELKVM_SYSTEM_MEMSIZE 16*1024*1024

struct kvm_vm;

struct kvm_pager {
	uint64_t guest_top_pm;
	int mode;
	struct kvm_vm *vm;
	struct mem_chunk system_chunk;
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

