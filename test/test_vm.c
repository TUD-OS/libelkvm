#include <check.h>
#include <errno.h>

#include <kvm.h>
#include <elkvm.h>
#include <vcpu.h>

#include "test_vm.h"

struct kvm_opts vm_test_opts;

void vm_setup() {
	kvm_init(&vm_test_opts);
}

void vm_teardown() {
	kvm_cleanup(&vm_test_opts);
}

START_TEST(test_kvm_vm_create) {

	struct kvm_vm the_vm;
	the_vm.fd = 0;
	the_vm.vcpus = NULL;
	int cpus = 1;
	int memory = 256*1024*1024;

	struct kvm_opts uninitialized_opts;
	uninitialized_opts.fd = 0;
	int err = kvm_vm_create(&uninitialized_opts, &the_vm, VM_MODE_X86_64, cpus, memory);
	ck_assert_int_eq(err, -EIO);
	ck_assert_int_eq(the_vm.fd, 0);
	ck_assert_ptr_eq(the_vm.vcpus, NULL);

	err = kvm_vm_create(&vm_test_opts, &the_vm, VM_MODE_X86_64, cpus, memory);
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

Suite *vm_suite() {
	Suite *s = suite_create("VM");

	TCase *tc_count = tcase_create("Count");
	tcase_add_test(tc_count, test_kvm_vm_vcpu_count);
	suite_add_tcase(s, tc_count);

	TCase *tc_create = tcase_create("Create");
	tcase_add_checked_fixture(tc_create, vm_setup, vm_teardown);
	tcase_add_test(tc_create, test_kvm_vm_create);
	suite_add_tcase(s, tc_create);
	return s;
}
