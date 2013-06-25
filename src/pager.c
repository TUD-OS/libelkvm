#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <elkvm.h>
#include <pager.h>

int kvm_pager_initialize(struct kvm_vm *vm, int mode) {
	if(vm->fd < 1) {
		return -1;
	}

	/* create a chunk for system data
	   TODO for now use a fixed size, what if bin is too large for that */	
	vm->pager.system_chunk.host_base_p = malloc(ELKVM_SYSTEM_MEMSIZE);
	if(vm->pager.system_chunk.host_base_p == NULL) {
		return -ENOMEM;
	}
	vm->pager.system_chunk.guest_base = 0x0;
	vm->pager.system_chunk.size = ELKVM_SYSTEM_MEMSIZE;

	int err = kvm_pager_create_page_tables(&vm->pager, mode);
	if(err) {
		return err;
	}

	return 0;
}

int kvm_pager_create_mem_chunk(struct kvm_pager *pager, int chunk_size, uint64_t guest_base) {
	struct mem_chunk *chunk = malloc(sizeof(struct mem_chunk));
	if(chunk == NULL) {
		return -ENOMEM;
	}

	chunk->host_base_p = malloc(chunk_size);
	chunk->guest_base = guest_base;
	chunk->size = chunk_size;

	if(pager->other_chunks == NULL) {
		pager->other_chunks = malloc(sizeof(struct chunk_list));
		pager->other_chunks->chunk = chunk;
		pager->other_chunks->next = NULL;
		return 0;
	}

	struct chunk_list *current = pager->other_chunks;
	while(current->next != NULL) {
		current = current->next;
	}

	current->next = malloc(sizeof(struct chunk_list));
	current = current->next;
	current->chunk = chunk;
	current->next = NULL;

	return 0;
}

int kvm_pager_create_page_tables(struct kvm_pager *pager, int mode) {
	if(pager == NULL) {
		return -1;
	}
	if(mode != PAGER_MODE_X86_64) {
		return -1;
	}

	if(pager->system_chunk.size < 0x400000) {
		return -1;
	}

	/* PML4 is put into the top 4MB of the system chunk */
	pager->host_pml4_p = pager->system_chunk.host_base_p + pager->system_chunk.size - 0x400000; 
	memset(pager->host_pml4_p, 0, 0x400000);
	pager->host_next_free_tbl_p = pager->host_pml4_p + 0x1000;

	return 0;
}

