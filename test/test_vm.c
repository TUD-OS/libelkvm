#include <check.h>
#include <errno.h>
#include <stdlib.h>
#include <stropts.h>
#include <unistd.h>

#include <kvm.h>
#include <elkvm.h>
#include <vcpu.h>

#include "test_vm.h"

struct elkvm_opts vm_test_opts;
int vm_fd;

void vm_setup() {
	elkvm_init(&vm_test_opts, 0, NULL, NULL);
	vm_fd = ioctl(vm_test_opts.fd, KVM_CREATE_VM, 0);
}

void vm_teardown() {
	close(vm_fd);
	elkvm_cleanup(&vm_test_opts);
}

START_TEST(test_kvm_vm_create) {

	struct kvm_vm the_vm;
	the_vm.fd = 0;
	the_vm.vcpus = NULL;
	int cpus = 1;
	int memory = 256*1024*1024;

	struct elkvm_opts uninitialized_opts;
	uninitialized_opts.fd = 0;
	int err = kvm_vm_create(&uninitialized_opts, &the_vm, VM_MODE_X86_64, cpus, 
			memory, NULL);
	ck_assert_int_eq(err, -EIO);
	ck_assert_int_eq(the_vm.fd, 0);
	ck_assert_ptr_eq(the_vm.vcpus, NULL);

	err = kvm_vm_create(&vm_test_opts, &the_vm, VM_MODE_X86_64, cpus, memory, NULL);
	ck_assert_int_eq(err, 0);
	ck_assert_int_gt(the_vm.fd, 0);
	ck_assert_ptr_ne(the_vm.vcpus, NULL);

	kvm_vm_destroy(&the_vm);

	//TODO test for -ENOMEM
}
END_TEST

START_TEST(test_kvm_vm_vcpu_count) {
	struct kvm_vm the_vm;
	the_vm.vcpus = NULL;

	int cpus = kvm_vm_vcpu_count(&the_vm);
	ck_assert_int_eq(cpus, 0);

	the_vm.vcpus = malloc(sizeof(struct vcpu_list));
	the_vm.vcpus->vcpu = NULL;
	the_vm.vcpus->next = NULL;

	cpus = kvm_vm_vcpu_count(&the_vm);
	ck_assert_int_eq(cpus, 0);

	the_vm.vcpus->vcpu = malloc(sizeof(struct kvm_vcpu));

	cpus = kvm_vm_vcpu_count(&the_vm);
	ck_assert_int_eq(cpus, 1);

	the_vm.vcpus->next = malloc(sizeof(struct vcpu_list));
	the_vm.vcpus->next->vcpu = NULL;
	the_vm.vcpus->next->next = NULL;

	cpus = kvm_vm_vcpu_count(&the_vm);
	ck_assert_int_eq(cpus, 1);

	the_vm.vcpus->next->vcpu = malloc(sizeof(struct kvm_vcpu));

	cpus = kvm_vm_vcpu_count(&the_vm);
	ck_assert_int_eq(cpus, 2);

	the_vm.vcpus->next->next = malloc(sizeof(struct vcpu_list));
	the_vm.vcpus->next->next->vcpu = malloc(sizeof(struct kvm_vcpu));
	the_vm.vcpus->next->next->next = NULL;

	cpus = kvm_vm_vcpu_count(&the_vm);
	ck_assert_int_eq(cpus, 3);
}
END_TEST

START_TEST(test_kvm_vm_map_system_chunk_valid) {
	struct kvm_vm the_vm;
	the_vm.fd = vm_fd;

	struct kvm_pager pager;
	pager.system_chunk.memory_size = 0x400000;
	void *ram_p;
	int err = posix_memalign(&ram_p, 0x1000, pager.system_chunk.memory_size);
	ck_assert_int_eq(err, 0);
	pager.system_chunk.userspace_addr = (__u64)ram_p;
	pager.system_chunk.guest_phys_addr = 0x0;
	pager.system_chunk.flags = 0;
	pager.system_chunk.slot = 0;

	err = kvm_vm_map_chunk(&the_vm, &pager.system_chunk);
	ck_assert_int_eq(err, 0);
}
END_TEST

START_TEST(test_kvm_vm_map_system_chunk_invalid) {
	struct kvm_vm the_vm;
	the_vm.fd = vm_fd;

	struct kvm_pager pager;
	pager.system_chunk.memory_size = 0x400000;
	pager.system_chunk.userspace_addr = (__u64)malloc(pager.system_chunk.memory_size);
	ck_assert_uint_ne(pager.system_chunk.userspace_addr, 0);
	ck_assert_uint_ne((pager.system_chunk.userspace_addr & ~0xFFF), 0);
	pager.system_chunk.guest_phys_addr = 0x0;
	pager.system_chunk.flags = 0;
	pager.system_chunk.slot = 0;

	int err = kvm_vm_map_chunk(&the_vm, &pager.system_chunk);
	ck_assert_int_ne(err, 0);
}
END_TEST

START_TEST(test_kvm_vm_map_system_chunk_multiple) {
	struct kvm_vm the_vm;
	the_vm.fd = vm_fd;

	struct kvm_pager pager;
	void *ram_p;
	pager.system_chunk.memory_size = 0x400000;
	int err = posix_memalign(&ram_p, 0x1000, pager.system_chunk.memory_size);
	ck_assert_int_eq(err, 0);
	pager.system_chunk.userspace_addr = (__u64)ram_p;
	pager.system_chunk.guest_phys_addr = 0x0;
	pager.system_chunk.flags = 0;
	pager.system_chunk.slot = 0;

	err = kvm_vm_map_chunk(&the_vm, &pager.system_chunk);
	ck_assert_int_eq(err, 0);

	pager.other_chunks = malloc(sizeof(struct chunk_list));
	ck_assert_ptr_ne(pager.other_chunks, NULL);
	pager.other_chunks->next = NULL;
	pager.other_chunks->chunk = malloc(sizeof(struct kvm_userspace_memory_region));
	ck_assert_ptr_ne(pager.other_chunks->chunk, NULL);

	struct kvm_userspace_memory_region *chunk = pager.other_chunks->chunk;
	chunk->memory_size = 0x1600000;
	err = posix_memalign(&ram_p, 0x1000, chunk->memory_size);
	ck_assert_int_eq(err, 0);
	chunk->userspace_addr = (__u64)ram_p;
	chunk->guest_phys_addr = 0x400000;
	chunk->flags = 0;
	chunk->slot = 1;

	err = kvm_vm_map_chunk(&the_vm, chunk);
	ck_assert_int_eq(err, 0);
}
END_TEST

Suite *vm_suite() {
	Suite *s = suite_create("VM");

	TCase *tc_count = tcase_create("Count");
	tcase_add_test(tc_count, test_kvm_vm_vcpu_count);
	suite_add_tcase(s, tc_count);

	TCase *tc_create = tcase_create("Create");
	tcase_add_checked_fixture(tc_create, vm_setup, vm_teardown);
	tcase_add_test(tc_create, test_kvm_vm_create);
	suite_add_tcase(s, tc_create);

	TCase *tc_map = tcase_create("Map mem_chunk");
	tcase_add_checked_fixture(tc_map, vm_setup, vm_teardown);
	tcase_add_test(tc_map, test_kvm_vm_map_system_chunk_valid);
	tcase_add_test(tc_map, test_kvm_vm_map_system_chunk_invalid);
	tcase_add_test(tc_map, test_kvm_vm_map_system_chunk_multiple);
	suite_add_tcase(s, tc_map);

	return s;
}
