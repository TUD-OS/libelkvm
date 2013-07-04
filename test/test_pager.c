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
	pager.system_chunk.guest_phys_addr = 0x0;
	pager.system_chunk.memory_size = ELKVM_SYSTEM_MEMSIZE;
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
	ck_assert_int_eq(cl->chunk->memory_size, size);
	ck_assert_int_eq(cl->chunk->guest_phys_addr, valid_guest_base);
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
	ck_assert_int_eq(cl->chunk->memory_size, size);
	ck_assert_int_eq(cl->chunk->guest_phys_addr, valid_guest_base);
	ck_assert_ptr_eq(cl->next, NULL);

	invalid_guest_base = valid_guest_base;
	valid_guest_base += size;
	err = kvm_pager_create_mem_chunk(&pager, size, valid_guest_base);
	ck_assert_int_eq(err,  0);
	ck_assert_ptr_ne(cl->next, NULL);
	cl = cl->next;
	ck_assert_int_eq(cl->chunk->memory_size, size);
	ck_assert_int_eq(cl->chunk->guest_phys_addr, valid_guest_base);
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

	pager.system_chunk.userspace_addr = (__u64)malloc(size);
	pager.system_chunk.memory_size = 0;

	int err = kvm_pager_create_page_tables(&pager, PAGER_MODE_X86_64);
	ck_assert_int_lt(err, 0);

	err = kvm_pager_create_page_tables(NULL, PAGER_MODE_X86_64);
	ck_assert_int_lt(err, 0);

	err = kvm_pager_create_page_tables(&pager, 9999);
	ck_assert_int_lt(err, 0);

	pager.system_chunk.memory_size = size;
	err = kvm_pager_create_page_tables(&pager, PAGER_MODE_X86_64);
	ck_assert_int_eq(err, 0);
	ck_assert_ptr_eq(pager.host_pml4_p, (void *)pager.system_chunk.userspace_addr);
	ck_assert_ptr_eq(pager.host_next_free_tbl_p, pager.host_pml4_p + 0x1000);

	free((void *)pager.system_chunk.userspace_addr);
}
END_TEST

START_TEST(test_kvm_pager_is_invalid_guest_base) {
	struct kvm_pager pager;
	pager.system_chunk.guest_phys_addr = 0x0;
	pager.system_chunk.memory_size = ELKVM_SYSTEM_MEMSIZE;
	pager.other_chunks = NULL;
	uint64_t guest_base = pager.system_chunk.guest_phys_addr;

	int invl = kvm_pager_is_invalid_guest_base(&pager, guest_base);
	ck_assert_int_eq(invl, 1);

	guest_base += ELKVM_SYSTEM_MEMSIZE-1;
	invl = kvm_pager_is_invalid_guest_base(&pager, guest_base);
	ck_assert_int_eq(invl, 1);

	guest_base++;
	invl = kvm_pager_is_invalid_guest_base(&pager, guest_base);
	ck_assert_int_eq(invl, 0);

	pager.other_chunks = malloc(sizeof(struct chunk_list));
	struct kvm_userspace_memory_region *chunk = 
		malloc(sizeof(struct kvm_userspace_memory_region));
	chunk->guest_phys_addr = 0x1000000;
	chunk->memory_size = 0x10000;
	pager.other_chunks->chunk = chunk;
	pager.other_chunks->next = NULL;

	invl = kvm_pager_is_invalid_guest_base(&pager, chunk->guest_phys_addr);
	ck_assert_int_eq(invl, 1);

	invl = kvm_pager_is_invalid_guest_base(&pager, chunk->guest_phys_addr + chunk->memory_size- 1);
	ck_assert_int_eq(invl, 1);

	invl = kvm_pager_is_invalid_guest_base(&pager, chunk->guest_phys_addr + chunk->memory_size);
	ck_assert_int_eq(invl, 0);

	invl = kvm_pager_is_invalid_guest_base(&pager, chunk->guest_phys_addr + chunk->memory_size + 0x234);
	ck_assert_int_eq(invl, 1);

	free(chunk);
	free(pager.other_chunks);
}
END_TEST

START_TEST(test_kvm_pager_append_mem_chunk) {
	struct kvm_pager pager;
	pager.other_chunks = NULL;

	struct kvm_userspace_memory_region r0;
	int count = kvm_pager_append_mem_chunk(&pager, &r0);
	ck_assert_int_eq(count, 0);

	struct kvm_userspace_memory_region r1;
	count = kvm_pager_append_mem_chunk(&pager, &r1);
	ck_assert_int_eq(count, 1);

	struct kvm_userspace_memory_region r2;
	count = kvm_pager_append_mem_chunk(&pager, &r2);
	ck_assert_int_eq(count, 2);

}
END_TEST

START_TEST(test_kvm_pager_find_region_for_host_p_nomem) {
	struct kvm_pager pager;
	pager.other_chunks = NULL;
	pager.system_chunk.userspace_addr = 0;
	pager.system_chunk.memory_size = 0;

	void *p = (void *)0x1000;
	struct kvm_userspace_memory_region *region = 
		kvm_pager_find_region_for_host_p(&pager, p);
	ck_assert_ptr_eq(region, NULL);
}
END_TEST

START_TEST(test_kvm_pager_find_region_for_host_p_system) {
	struct kvm_pager pager;
	pager.other_chunks = NULL;
	pager.system_chunk.userspace_addr = 0;
	pager.system_chunk.memory_size = 0x400000;

	void *p = (void *)0x1000;
	struct kvm_userspace_memory_region *region = 
		kvm_pager_find_region_for_host_p(&pager, p);
	ck_assert_ptr_eq(region, &pager.system_chunk);
}
END_TEST

START_TEST(test_kvm_pager_find_region_for_host_p_user) {
	struct kvm_pager pager;
	pager.system_chunk.userspace_addr = 0;
	pager.system_chunk.memory_size = 0x400000;

	pager.other_chunks = malloc(sizeof(struct chunk_list));
	pager.other_chunks->chunk = malloc(sizeof(struct kvm_userspace_memory_region));
	pager.other_chunks->next = NULL;

	struct kvm_userspace_memory_region *chunk = pager.other_chunks->chunk;
	chunk->userspace_addr = 0x400000;
	chunk->memory_size = 0x100000;

	void *p = (void *)0x427500;
	struct kvm_userspace_memory_region *region = 
		kvm_pager_find_region_for_host_p(&pager, p);
	ck_assert_ptr_eq(region, pager.other_chunks->chunk);
}
END_TEST

START_TEST(test_kvm_pager_find_region_for_host_p_system_edge) {
	struct kvm_pager pager;
	pager.other_chunks = NULL;
	pager.system_chunk.userspace_addr = 0;
	pager.system_chunk.memory_size = 0x400000;

	void *p = (void *)0x0;
	struct kvm_userspace_memory_region *region = 
		kvm_pager_find_region_for_host_p(&pager, p);
	ck_assert_ptr_eq(region, &pager.system_chunk);

	p = (void *)0x400000;
	region = kvm_pager_find_region_for_host_p(&pager, p);
	ck_assert_ptr_eq(region, NULL);
}
END_TEST

START_TEST(test_kvm_pager_find_region_for_host_p_user_edge) {
	struct kvm_pager pager;
	pager.system_chunk.userspace_addr = 0;
	pager.system_chunk.memory_size = 0x400000;

	pager.other_chunks = malloc(sizeof(struct chunk_list));
	pager.other_chunks->chunk = malloc(sizeof(struct kvm_userspace_memory_region));
	pager.other_chunks->next = NULL;

	struct kvm_userspace_memory_region *chunk = pager.other_chunks->chunk;
	chunk->userspace_addr = 0x400000;
	chunk->memory_size = 0x100000;

	void *p = (void *)0x400000;
	struct kvm_userspace_memory_region *region = 
		kvm_pager_find_region_for_host_p(&pager, p);
	ck_assert_ptr_eq(region, pager.other_chunks->chunk);

	p = (void *)0x500000;
	region = kvm_pager_find_region_for_host_p(&pager, p);
	ck_assert_ptr_eq(region, NULL);
}
END_TEST

START_TEST(test_kvm_pager_create_mapping_invalid_host) {
	struct kvm_pager pager;
	pager.system_chunk.userspace_addr = 0;
	pager.system_chunk.memory_size = 0;

	void *p = (void *)0x1000;
	int err = kvm_pager_create_mapping(&pager, p, 0x400000);
	ck_assert_int_eq(err, -1);

}
END_TEST

START_TEST(test_kvm_pager_create_valid_mappings) {
	struct kvm_pager pager;
	pager.system_chunk.userspace_addr = 0;
	pager.system_chunk.memory_size = 0x400000;

	void *p = (void *)0x1000;
	uint64_t guest_virtual_addr = 0x600000;
	int err = kvm_pager_create_mapping(&pager, p, guest_virtual_addr);
	ck_assert_int_eq(err, 0);

	void *host_resolved_p = kvm_pager_get_host_p(&pager, guest_virtual_addr);
	ck_assert_ptr_eq(p, host_resolved_p);

	p = (void *)0xe10;
	guest_virtual_addr = 0x400e10;
	err = kvm_pager_create_mapping(&pager, p, guest_virtual_addr);
	ck_assert_int_eq(err, 0);

	host_resolved_p = kvm_pager_get_host_p(&pager, guest_virtual_addr);
	ck_assert_ptr_eq(p, host_resolved_p);

	p = (void *)0x40;
	guest_virtual_addr = 0x400040;
	err = kvm_pager_create_mapping(&pager, p, guest_virtual_addr);
	ck_assert_int_eq(err, 0);

	host_resolved_p = kvm_pager_get_host_p(&pager, guest_virtual_addr);
	ck_assert_ptr_eq(p, host_resolved_p);
}
END_TEST

START_TEST(test_kvm_pager_create_same_mapping) {
	struct kvm_pager pager;
	pager.system_chunk.userspace_addr = 0;
	pager.system_chunk.memory_size = 0x400000;

	void *p = (void *)0x1000;
	uint64_t guest_virtual_addr = 0x600000;
	int err = kvm_pager_create_mapping(&pager, p, guest_virtual_addr);
	ck_assert_int_eq(err, 0);

	p = (void *)0x2000;
	err = kvm_pager_create_mapping(&pager, p, guest_virtual_addr);
	ck_assert_int_eq(err, -1);
}
END_TEST

START_TEST(test_kvm_pager_create_mapping_invalid_offset) {
	struct kvm_pager pager;
	pager.system_chunk.userspace_addr = 0;
	pager.system_chunk.memory_size = 0x400000;

	void *p = (void *)0x1e10;
	uint64_t guest_virtual_addr = 0x600000;
	int err = kvm_pager_create_mapping(&pager, p, guest_virtual_addr);
	ck_assert_int_eq(err, -1);

}
END_TEST

START_TEST(test_kvm_pager_create_entry) {
	struct kvm_pager pager;
	pager.system_chunk.userspace_addr = 0;
	pager.system_chunk.memory_size = 0x400000;
	int err = posix_memalign(&pager.host_pml4_p, 0x1000, 0x2000);
	ck_assert_int_eq(err, 0);
	pager.host_next_free_tbl_p = pager.host_pml4_p + 0x1000;
	memset(pager.host_pml4_p, 0, 0x2000);

	uint64_t guest_virtual = 0x400400;
	uint64_t *entry = pager.host_pml4_p + (5 * sizeof(uint64_t));
	err = kvm_pager_create_entry(&pager, entry, guest_virtual, 39, 47);
	ck_assert_int_eq(err, 0);
	ck_assert_int_eq(*entry & 0x1, 1);
	ck_assert_int_eq(*entry >> 12, (uint64_t)(pager.host_pml4_p + 0x1000) >> 12);

	free(pager.host_pml4_p);
}
END_TEST

START_TEST(test_kvm_pager_find_table_entry) {
	struct kvm_pager pager;
	int err = posix_memalign(&pager.host_pml4_p, 0x1000, 0x2000);
	ck_assert_int_eq(err, 0);
	pager.host_next_free_tbl_p = pager.host_pml4_p + 0x1000;
	memset(pager.host_pml4_p, 0, 0x2000);

	/* this should result in an offset of 2 into the pml4 */
	uint64_t guest_virtual = 0x14000400400;
	uint64_t *expected_entry = pager.host_pml4_p + (2 * sizeof(uint64_t));
	*expected_entry = 0x1001;

	uint64_t *entry = kvm_pager_find_table_entry(&pager, pager.host_pml4_p, guest_virtual, 39, 47);
	ck_assert_ptr_eq(entry, expected_entry);
}
END_TEST

Suite *pager_suite() {
	Suite *s = suite_create("Pager");

	//TODO include newest tests!
	
	TCase *tc_create_entry = tcase_create("Create PT entry");
	tcase_add_test(tc_create_entry, test_kvm_pager_create_entry);
	suite_add_tcase(s, tc_create_entry);

	TCase *tc_find_entry = tcase_create("Find PT entry");
	tcase_add_test(tc_find_entry, test_kvm_pager_find_table_entry);
	suite_add_tcase(s, tc_find_entry);

	TCase *tc_find_region = tcase_create("Find Memory Region");
	tcase_add_test(tc_find_region, test_kvm_pager_find_region_for_host_p_nomem);
	tcase_add_test(tc_find_region, test_kvm_pager_find_region_for_host_p_system);
	tcase_add_test(tc_find_region, test_kvm_pager_find_region_for_host_p_user);
	tcase_add_test(tc_find_region, test_kvm_pager_find_region_for_host_p_system_edge);
	tcase_add_test(tc_find_region, test_kvm_pager_find_region_for_host_p_user_edge);
	suite_add_tcase(s, tc_find_region);

	TCase *tc_create_mappings = tcase_create("Create Virtual Memory Mappings");
	tcase_add_test(tc_create_mappings, test_kvm_pager_create_mapping_invalid_host);
	tcase_add_test(tc_create_mappings, test_kvm_pager_create_valid_mappings);
	tcase_add_test(tc_create_mappings, test_kvm_pager_create_same_mapping);
	tcase_add_test(tc_create_mappings, test_kvm_pager_create_mapping_invalid_offset);
	suite_add_tcase(s, tc_create_mappings);

	TCase *tc_append_mem_chunk = tcase_create("Append Mem Chunk");
	tcase_add_test(tc_append_mem_chunk, test_kvm_pager_append_mem_chunk);
	suite_add_tcase(s, tc_append_mem_chunk);

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
