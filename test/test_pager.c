#include <check.h>

#include <errno.h>
#include <stdlib.h>
#include <stropts.h>

#include <elkvm.h>
#include <pager.h>

#include "test_pager.h"

struct kvm_opts pager_test_opts;
int vm_fd;

void pager_setup() {
	kvm_init(&pager_test_opts);
	vm_fd = ioctl(pager_test_opts.fd, KVM_CREATE_VM, 0);
}

void pager_teardown() {
	kvm_cleanup(&pager_test_opts);
}

START_TEST(test_kvm_pager_initialize) {
	struct kvm_vm the_vm;
	the_vm.fd = 0;

	int err = kvm_pager_initialize(&the_vm, PAGER_MODE_X86_64);
	ck_assert_int_lt(err, 0);

	the_vm.fd = vm_fd;

	err = kvm_pager_initialize(&the_vm, 9999);
	ck_assert_int_lt(err, 0);


	err = kvm_pager_initialize(&the_vm, PAGER_MODE_X86_64);
	ck_assert_int_eq(err, 0);
}
END_TEST

START_TEST(test_kvm_pager_create_mem_chunk) {
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
	ck_assert_int_eq(err, -EIO);
	ck_assert_ptr_eq(pager.other_chunks, NULL);

	err = kvm_pager_create_mem_chunk(&pager, size, invalid_guest_base);
	ck_assert_int_eq(err, -EIO);
	ck_assert_ptr_eq(pager.other_chunks, NULL);

	err = kvm_pager_create_mem_chunk(&pager, size, valid_guest_base);
	ck_assert_int_eq(err, 0);
	ck_assert_ptr_ne(pager.other_chunks, NULL);
	struct chunk_list *cl = pager.other_chunks;
	ck_assert_int_eq(cl->chunk->size, size);
	ck_assert_int_eq(cl->chunk->guest_base, valid_guest_base);
	ck_assert_ptr_eq(cl->next, NULL);

	invalid_guest_base = valid_guest_base;
	valid_guest_base += size;
	err = kvm_pager_create_mem_chunk(&pager, size, invalid_guest_base);
	ck_assert_int_eq(err, -EIO);
	ck_assert_ptr_eq(cl->next, NULL);

	err = kvm_pager_create_mem_chunk(&pager, size, valid_guest_base);
	ck_assert_int_eq(err, 0);
	ck_assert_ptr_ne(cl->next, NULL);
	cl = cl->next;
	ck_assert_int_eq(cl->chunk->size, size);
	ck_assert_int_eq(cl->chunk->guest_base, valid_guest_base);
	ck_assert_ptr_eq(cl->next, NULL);

	invalid_guest_base = valid_guest_base;
	valid_guest_base += size;
	err = kvm_pager_create_mem_chunk(&pager, size, valid_guest_base);
	ck_assert_int_eq(err,  0);
	ck_assert_ptr_ne(cl->next, NULL);
	cl = cl->next;
	ck_assert_int_eq(cl->chunk->size, size);
	ck_assert_int_eq(cl->chunk->guest_base, valid_guest_base);
	ck_assert_ptr_eq(cl->next, NULL);


	invalid_guest_base = valid_guest_base;
	valid_guest_base += size;
	err = kvm_pager_create_mem_chunk(&pager, invalid_size, valid_guest_base);
	ck_assert_int_eq(err, -EIO);
	ck_assert_ptr_eq(cl->next, NULL);

	unaligned_guest_base = valid_guest_base + 0x234;
	err = kvm_pager_create_mem_chunk(&pager,size, unaligned_guest_base);
	ck_assert_int_eq(err, -EIO);
	ck_assert_ptr_eq(cl->next, NULL);

}
END_TEST

START_TEST(test_kvm_pager_create_page_tables) {
	struct kvm_pager pager;
	int size = 0x400000;

	pager.system_chunk.host_base_p = malloc(size);
	pager.system_chunk.size = 0;

	int err = kvm_pager_create_page_tables(&pager, PAGER_MODE_X86_64);
	ck_assert_int_lt(err, 0);

	err = kvm_pager_create_page_tables(NULL, PAGER_MODE_X86_64);
	ck_assert_int_lt(err, 0);

	err = kvm_pager_create_page_tables(&pager, 9999);
	ck_assert_int_lt(err, 0);

	pager.system_chunk.size = size;
	err = kvm_pager_create_page_tables(&pager, PAGER_MODE_X86_64);
	ck_assert_int_eq(err, 0);
	ck_assert_ptr_eq(pager.host_pml4_p, pager.system_chunk.host_base_p);
	ck_assert_ptr_eq(pager.host_next_free_tbl_p, pager.host_pml4_p + 0x1000);

	free(pager.system_chunk.host_base_p);
}
END_TEST

START_TEST(test_kvm_pager_is_invalid_guest_base) {
	struct kvm_pager pager;
	pager.system_chunk.guest_base = 0x0;
	pager.system_chunk.size = ELKVM_SYSTEM_MEMSIZE;
	pager.other_chunks = NULL;
	uint64_t guest_base = pager.system_chunk.guest_base;

	int invl = kvm_pager_is_invalid_guest_base(&pager, guest_base);
	ck_assert_int_eq(invl, 1);

	guest_base += ELKVM_SYSTEM_MEMSIZE-1;
	invl = kvm_pager_is_invalid_guest_base(&pager, guest_base);
	ck_assert_int_eq(invl, 1);

	guest_base++;
	invl = kvm_pager_is_invalid_guest_base(&pager, guest_base);
	ck_assert_int_eq(invl, 0);

	pager.other_chunks = malloc(sizeof(struct chunk_list));
	struct mem_chunk *chunk = malloc(sizeof(struct mem_chunk));
	chunk->guest_base = 0x1000000;
	chunk->size = 0x10000;
	pager.other_chunks->chunk = chunk;
	pager.other_chunks->next = NULL;

	invl = kvm_pager_is_invalid_guest_base(&pager, chunk->guest_base);
	ck_assert_int_eq(invl, 1);

	invl = kvm_pager_is_invalid_guest_base(&pager, chunk->guest_base + chunk->size- 1);
	ck_assert_int_eq(invl, 1);

	invl = kvm_pager_is_invalid_guest_base(&pager, chunk->guest_base + chunk->size);
	ck_assert_int_eq(invl, 0);

	invl = kvm_pager_is_invalid_guest_base(&pager, chunk->guest_base + chunk->size + 0x234);
	ck_assert_int_eq(invl, 1);

	free(chunk);
	free(pager.other_chunks);
}
END_TEST

Suite *pager_suite() {
	Suite *s = suite_create("Pager");

	TCase *tc_guest_base = tcase_create("Guest Base");
	tcase_add_test(tc_guest_base, test_kvm_pager_is_invalid_guest_base);
	suite_add_tcase(s, tc_guest_base);

	TCase *tc_page_tables = tcase_create("Create Page Tables");
	tcase_add_test(tc_page_tables, test_kvm_pager_create_page_tables);
	suite_add_tcase(s, tc_page_tables);

	TCase *tc_init = tcase_create("Initialize");
	tcase_add_checked_fixture(tc_init, pager_setup, pager_teardown);
	tcase_add_test(tc_init, test_kvm_pager_initialize);
	suite_add_tcase(s, tc_init);

	TCase *tc_mem_chunk = tcase_create("Create Mem Chunk");
	tcase_add_test(tc_mem_chunk, test_kvm_pager_create_mem_chunk);
	suite_add_tcase(s, tc_mem_chunk);

	return s;
}
