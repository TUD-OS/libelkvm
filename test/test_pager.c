#include <CUnit/Basic.h>

#include <stdlib.h>
#include <stropts.h>

#include <elkvm.h>
#include <pager.h>

#include "test_pager.h"

struct kvm_opts pager_test_opts;
int vm_fd;

int init_pager_suite() {
	int err = kvm_init(&pager_test_opts);
	if(err) {
		return err;
	}

	vm_fd = ioctl(pager_test_opts.fd, KVM_CREATE_VM, 0);
	if(vm_fd < 0) {
		return -1;
	}
	
	return 0;
}

int clean_pager_suite() {
	kvm_cleanup(&pager_test_opts);
	return 0;
}

void test_kvm_pager_initialize() {
	struct kvm_vm the_vm;

	int err = kvm_pager_initialize(&the_vm, PAGER_MODE_X86_64);
	CU_ASSERT(0 > err);

	the_vm.fd = vm_fd;

	err = kvm_pager_initialize(&the_vm, 9999);
	CU_ASSERT(0 > err);
	

	err = kvm_pager_initialize(&the_vm, PAGER_MODE_X86_64);
	CU_ASSERT(0 == err);
}

void test_kvm_pager_create_mem_chunk() {
	CU_ASSERT(0);
}

void test_kvm_pager_add_mem_chunk() {
	struct kvm_pager pager;
	pager.other_chunks = NULL;
	struct mem_chunk chunk;
	struct mem_chunk chunk2;
	struct mem_chunk chunk3;

	CU_ASSERT(pager.other_chunks == NULL);
	kvm_pager_add_mem_chunk(&pager, &chunk);
	CU_ASSERT(pager.other_chunks != NULL);
	CU_ASSERT(pager.other_chunks->chunk == &chunk);
	CU_ASSERT(pager.other_chunks->next == NULL);

	kvm_pager_add_mem_chunk(&pager, &chunk2);
	struct chunk_list *cl = pager.other_chunks;
	CU_ASSERT(cl->chunk == &chunk);
	cl = cl->next;
	CU_ASSERT(cl->chunk == &chunk2);
	CU_ASSERT(cl->next == NULL);

	kvm_pager_add_mem_chunk(&pager, &chunk3);
	cl = pager.other_chunks;
	CU_ASSERT(cl->chunk == &chunk);
	cl = cl->next;
	CU_ASSERT(cl->chunk == &chunk2);
	cl = cl->next;
	CU_ASSERT(cl->chunk == &chunk3);
	CU_ASSERT(cl->next == NULL);
}

void test_kvm_pager_create_page_tables() {
	struct kvm_pager pager;
	int size = 0x400000;

	pager.system_chunk.host_base_p = malloc(size);
	pager.system_chunk.size = 0;

	int err = kvm_pager_create_page_tables(&pager, PAGER_MODE_X86_64);
	CU_ASSERT(err < 0);

	err = kvm_pager_create_page_tables(NULL, PAGER_MODE_X86_64);
	CU_ASSERT(err < 0);

	err = kvm_pager_create_page_tables(&pager, 9999);
	CU_ASSERT(err < 0);
	
	pager.system_chunk.size = size;
	err = kvm_pager_create_page_tables(&pager, PAGER_MODE_X86_64);
	CU_ASSERT(err == 0);
	CU_ASSERT(pager.host_pml4_p == pager.system_chunk.host_base_p);
	CU_ASSERT(pager.host_next_free_tbl_p == pager.host_pml4_p + 0x1000);

	free(pager.system_chunk.host_base_p);
}

