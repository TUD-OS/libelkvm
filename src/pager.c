#include <stdlib.h>
#include <string.h>

#include <elkvm.h>
#include <pager.h>

int kvm_pager_initialize(struct kvm_vm *vm, int mode) {
	if(vm->fd < 1) {
		return -1;
	}

	/* create a chunk for system data
	   TODO for now use a fixed size */	
	struct mem_chunk *sys_chunk = kvm_pager_create_mem_chunk(&vm->pager, KVM_SYSTEM_MEMSIZE);
	if(sys_chunk == NULL) {
		return -1;
	}

	vm->pager.system_chunk = *sys_chunk;

	int err = kvm_pager_create_page_tables(&vm->pager, mode);
	if(err) {
		return -1;
	}

	return 0;
}

void kvm_pager_add_mem_chunk(struct kvm_pager *pager, struct mem_chunk *chunk) {
	if(pager->other_chunks == NULL) {
		pager->other_chunks = malloc(sizeof(struct chunk_list));
		pager->other_chunks->chunk = chunk;
		pager->other_chunks->next = NULL;
		return;
	}

	struct chunk_list *current = pager->other_chunks;
	while(current->next != NULL) {
		current = current->next;
	}

	current->next = malloc(sizeof(struct chunk_list));
	current = current->next;
	current->chunk = chunk;
	current->next = NULL;
}

struct mem_chunk *kvm_pager_create_mem_chunk(struct kvm_pager *pager, int chunk_size) {
	return NULL;
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

