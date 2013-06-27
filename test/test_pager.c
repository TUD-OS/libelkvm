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
	the_vm.fd = 0;

	int err = kvm_pager_initialize(&the_vm, PAGER_MODE_X86_64);
	CU_ASSERT(0 > err);

	the_vm.fd = vm_fd;

	err = kvm_pager_initialize(&the_vm, 9999);
	CU_ASSERT(0 > err);


	err = kvm_pager_initialize(&the_vm, PAGER_MODE_X86_64);
	CU_ASSERT_EQUAL(err, 0);
}

void test_kvm_pager_create_mem_chunk() {
	int size = 0x400000;
	int invalid_size = 0x400234;
	uint64_t invalid_guest_base = 0;
	uint64_t valid_guest_base = 0x100000000;
	uint64_t unaligned_guest_base;
	struct kvm_pager pager;
	pager.system_chunk.guest_base = 0x0;
	pager.system_chunk.size = ELKVM_SYSTEM_MEMSIZE;
	pager.other_chunks = NULL;

	int err = kvm_pager_create_mem_chunk(NULL, size, valid_guest_base);
	CU_ASSERT_EQUAL(err, -EIO);
	CU_ASSERT_PTR_NULL(pager.other_chunks);

	err = kvm_pager_create_mem_chunk(&pager, size, invalid_guest_base);
	CU_ASSERT_EQUAL(err, -EIO);
	CU_ASSERT_PTR_NULL(pager.other_chunks);

	err = kvm_pager_create_mem_chunk(&pager, size, valid_guest_base);
	CU_ASSERT_EQUAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(pager.other_chunks);
	struct chunk_list *cl = pager.other_chunks;
	CU_ASSERT_EQUAL(cl->chunk->size, size);
	CU_ASSERT_EQUAL(cl->chunk->guest_base, valid_guest_base);
	CU_ASSERT_PTR_NULL(cl->next);

	invalid_guest_base = valid_guest_base;
	valid_guest_base += size;
	err = kvm_pager_create_mem_chunk(&pager, size, invalid_guest_base);
	CU_ASSERT_EQUAL(err, -EIO);
	CU_ASSERT_PTR_NULL(cl->next);

	err = kvm_pager_create_mem_chunk(&pager, size, valid_guest_base);
	CU_ASSERT_EQUAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(cl->next);
	cl = cl->next;
	CU_ASSERT_EQUAL(cl->chunk->size, size);
	CU_ASSERT_EQUAL(cl->chunk->guest_base, valid_guest_base);
	CU_ASSERT_PTR_NULL(cl->next);

	invalid_guest_base = valid_guest_base;
	valid_guest_base += size;
	err = kvm_pager_create_mem_chunk(&pager, size, valid_guest_base);
	CU_ASSERT_EQUAL(err,  0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(cl->next);
	cl = cl->next;
	CU_ASSERT_EQUAL(cl->chunk->size, size);
	CU_ASSERT_EQUAL(cl->chunk->guest_base, valid_guest_base);
	CU_ASSERT_PTR_NULL(cl->next);


	invalid_guest_base = valid_guest_base;
	valid_guest_base += size;
	err = kvm_pager_create_mem_chunk(&pager, invalid_size, valid_guest_base);
	CU_ASSERT_EQUAL(err, -EIO);
	CU_ASSERT_PTR_NULL(cl->next);

	unaligned_guest_base = valid_guest_base + 0x234;
	err = kvm_pager_create_mem_chunk(&pager,size, unaligned_guest_base);
	CU_ASSERT_EQUAL(err, -EIO);
	CU_ASSERT_PTR_NULL(cl->next);

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
	CU_ASSERT_EQUAL(err, 0);
	CU_ASSERT_EQUAL(pager.host_pml4_p, pager.system_chunk.host_base_p);
	CU_ASSERT_EQUAL(pager.host_next_free_tbl_p, pager.host_pml4_p + 0x1000);

	free(pager.system_chunk.host_base_p);
}

void test_kvm_pager_is_invalid_guest_base() {
	struct kvm_pager pager;
	pager.system_chunk.guest_base = 0x0;
	pager.system_chunk.size = ELKVM_SYSTEM_MEMSIZE;
	pager.other_chunks = NULL;
	uint64_t guest_base = pager.system_chunk.guest_base;

	int invl = kvm_pager_is_invalid_guest_base(&pager, guest_base);
	CU_ASSERT_EQUAL(invl, 1);

	guest_base += ELKVM_SYSTEM_MEMSIZE-1;
	invl = kvm_pager_is_invalid_guest_base(&pager, guest_base);
	CU_ASSERT_EQUAL(invl, 1);

	guest_base++;
	invl = kvm_pager_is_invalid_guest_base(&pager, guest_base);
	CU_ASSERT_EQUAL(invl, 0);

	pager.other_chunks = malloc(sizeof(struct chunk_list));
	struct mem_chunk *chunk = malloc(sizeof(struct mem_chunk));
	chunk->guest_base = 0x1000000;
	chunk->size = 0x10000;
	pager.other_chunks->chunk = chunk;
	pager.other_chunks->next = NULL;

	invl = kvm_pager_is_invalid_guest_base(&pager, chunk->guest_base);
	CU_ASSERT_EQUAL(invl, 1);

	invl = kvm_pager_is_invalid_guest_base(&pager, chunk->guest_base + chunk->size- 1);
	CU_ASSERT_EQUAL(invl, 1);

	invl = kvm_pager_is_invalid_guest_base(&pager, chunk->guest_base + chunk->size);
	CU_ASSERT_EQUAL(invl, 0);

	invl = kvm_pager_is_invalid_guest_base(&pager, chunk->guest_base + chunk->size + 0x234);
	CU_ASSERT_EQUAL(invl, 1);

	free(chunk);
	free(pager.other_chunks);
}
