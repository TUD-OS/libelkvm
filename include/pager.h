#pragma once

#include <inttypes.h>
#include <stdint.h>

#include <mem_chunk.h>

#define PAGER_MODE_X86     1
#define PAGER_MODE_X86_E   2
#define PAGER_MODE_X86_X64 3

struct kvm_vm;

struct kvm_pager {
	uint64_t guest_top_pm;
	int mode;
	struct kvm_vm *vm;
	struct mem_chunk system_chunk;
	struct mem_chunk *other_chunks;
};

/*
	Initialize the Pager with the given mode
*/
int kvm_pager_initialize(struct kvm_vm *, int);

/*
	Let Pager create a mem chunk of the given size
*/
int kvm_pager_create_mem_chunk(struct kvm_pager *, int);

