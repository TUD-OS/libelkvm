#include <stdlib.h>

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
	
}
