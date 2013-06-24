#pragma once

#include <inttypes.h>
#include <stdint.h>

#include <mem_chunk.h>

#define PAGER_MODE_X86     1
#define PAGER_MODE_X86_E   2
#define PAGER_MODE_X86_64  3

#define KVM_SYSTEM_MEMSIZE 16*1024*1024

struct kvm_vm;

struct kvm_pager {
	uint64_t guest_top_pm;
	int mode;
	struct kvm_vm *vm;
	struct mem_chunk system_chunk;
	struct chunk_list *other_chunks;
};

/*
	Initialize the Pager with the given mode
*/
int kvm_pager_initialize(struct kvm_vm *, int);

/*
	Let Pager create a mem chunk of the given size
*/
struct mem_chunk *kvm_pager_create_mem_chunk(struct kvm_pager *, int);

/*
	Create Page Tables according to given mode
*/
int kvm_pager_create_page_tables(struct kvm_pager *, int);

/*
	Add a new mem_chunk to the beginning of the list of mem_chunks
*/
void kvm_pager_add_mem_chunk(struct kvm_pager *, struct mem_chunk *);
