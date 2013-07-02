#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <elkvm.h>
#include <pager.h>

int kvm_pager_initialize(struct kvm_vm *vm, int mode) {
	if(vm->fd < 1) {
		return -1;
	}

	vm->pager.mode = mode;

	/* create a chunk for system data
	   TODO for now use a fixed size, what if bin is too large for that */	
	void *system_chunk_p;
	int err = posix_memalign(&system_chunk_p, 0x1000, ELKVM_SYSTEM_MEMSIZE);
	if(err) {
		return err;
	}

	vm->pager.system_chunk.userspace_addr = (__u64)system_chunk_p;
	vm->pager.system_chunk.guest_phys_addr = 0x0;
	vm->pager.system_chunk.memory_size = ELKVM_SYSTEM_MEMSIZE;
	vm->pager.system_chunk.flags = 0;
	vm->pager.system_chunk.slot = 0;

	vm->pager.other_chunks = NULL;

	err = kvm_pager_create_page_tables(&vm->pager, mode);
	if(err) {
		return err;
	}

	return 0;
}

int kvm_pager_create_mem_chunk(struct kvm_pager *pager, int chunk_size, uint64_t guest_base) {

	if(pager == NULL) {
		return -EIO;
	}

	/* keep sizes page aligned */
	if((chunk_size & ~0xFFF) != chunk_size) {
		return -EIO;
	}

	if(kvm_pager_is_invalid_guest_base(pager, guest_base)) {
		return -EIO;
	}

	struct kvm_userspace_memory_region *chunk = 
		malloc(sizeof(struct kvm_userspace_memory_region));
	if(chunk == NULL) {
		return -ENOMEM;
	}

	void *chunk_host_p;
	int err = posix_memalign(&chunk_host_p, 0x1000, chunk_size);
	if(err) {
		return err;
	}

	chunk->userspace_addr = (__u64)chunk_host_p; 
	chunk->guest_phys_addr = guest_base;
	chunk->memory_size = chunk_size;
	chunk->flags = 0;

	int chunk_count = kvm_pager_append_mem_chunk(pager, chunk);
	if(chunk_count < 0) {
		goto out_free_chunk_base;
	}
	/* system chunk has slot 0, so we need to add 1 to all user chunks */
	chunk->slot = chunk_count + 1;

	return 0;

out_free_chunk_base:
	free((void *)chunk->userspace_addr);
out_free_chunk:
	free(chunk);
	return -ENOMEM;	
}

int kvm_pager_append_mem_chunk(struct kvm_pager *pager,
		struct kvm_userspace_memory_region *chunk) {

	if(pager->other_chunks == NULL) {
		pager->other_chunks = malloc(sizeof(struct chunk_list));
		if(pager->other_chunks == NULL) {
			return -ENOMEM;
		}
		pager->other_chunks->chunk = chunk;
		pager->other_chunks->next = NULL;
		return 0;
	}

	int chunk_count = 0;
	struct chunk_list *current = pager->other_chunks;
	while(current->next != NULL) {
		chunk_count++;
		current = current->next;
	}

	current->next = malloc(sizeof(struct chunk_list));
	if(current->next == NULL) {
		return -ENOMEM;
	}

	chunk_count++;
	current = current->next;
	current->chunk = chunk;
	current->next = NULL;

	return chunk_count;
}

int kvm_pager_create_page_tables(struct kvm_pager *pager, int mode) {
	if(pager == NULL) {
		return -1;
	}
	if(mode != PAGER_MODE_X86_64) {
		return -1;
	}

	if(pager->system_chunk.memory_size < 0x400000) {
		return -1;
	}

	/* PML4 is put into the top 4MB of the system chunk */
	pager->host_pml4_p = (void *)pager->system_chunk.userspace_addr + 
		pager->system_chunk.memory_size - 0x400000; 
	memset(pager->host_pml4_p, 0, 0x400000);
	pager->host_next_free_tbl_p = pager->host_pml4_p + 0x1000;

	return 0;
}

int kvm_pager_is_invalid_guest_base(struct kvm_pager *pager, uint64_t guest_base) {

	/* keep base addresses page aligned */
	if((guest_base & ~0xFFF) != guest_base) {
		return 1;
	}

	if(pager->system_chunk.guest_phys_addr <= guest_base && 
			guest_base < pager->system_chunk.guest_phys_addr + 
				pager->system_chunk.memory_size) {
		return 1;
	}

	struct chunk_list *cl = pager->other_chunks;
	while(cl != NULL) {
		if(cl->chunk->guest_phys_addr <= guest_base && 
				guest_base < cl->chunk->guest_phys_addr + cl->chunk->memory_size) {
			return 1;
		}
		cl = cl->next;
	}

	return 0;
}

struct kvm_userspace_memory_region *
	kvm_pager_find_region_for_host_p(struct kvm_pager *pager, void *host_mem_p) {
		if(((void *)pager->system_chunk.userspace_addr <= host_mem_p) &&
				(host_mem_p < ((void *)pager->system_chunk.userspace_addr + 
					pager->system_chunk.memory_size))) {
			return &pager->system_chunk;
		}

		struct chunk_list *cl = pager->other_chunks;
		while(cl != NULL) {
			struct kvm_userspace_memory_region *region = cl->chunk;
			if((void *)region->userspace_addr <= host_mem_p &&
					host_mem_p < ((void *)region->userspace_addr + region->memory_size)) {
				return region;
			}
			cl = cl->next;
		}

		return NULL;
	}

