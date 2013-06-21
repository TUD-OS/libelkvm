#pragma once

#define PAGER_MODE_X86     1
#define PAGER_MODE_X86_E   2
#define PAGER_MODE_X86_X64 3

struct pager {
	uint64_t guest_top_pm;
	int mode;
	struct kvm_vm vm;
	struct mem_chunk system_chunk;
	struct mem_chunk *other_chunks;
}

/*
	Initialize the Pager with the given mode
*/
int pager_initialize(struct pager *, int, struct kvm_vm);

/*
	Let Pager create a mem chunk of the given size
*/
int pager_create_mem_chunk(struct pager *, int);

