
#include <CUnit/Basic.h>

#include <kvm.h>
#include <elkvm.h>
#include <vcpu.h>

#include "test_vm.h"

struct kvm_opts vm_test_opts;

int init_vm_suite() {
	int err = kvm_init(&vm_test_opts);
	return err;
}

int clean_vm_suite() {
	kvm_cleanup(&vm_test_opts);
	return 0;
}

void test_kvm_vm_create() {

	struct kvm_vm the_vm;
	the_vm.fd = 0;
	the_vm.vcpus = NULL;
	int cpus = 1;
	int memory = 256*1024*1024;

	struct kvm_opts uninitialized_opts;
	uninitialized_opts.fd = 0;
	int err = kvm_vm_create(&uninitialized_opts, &the_vm, VM_MODE_X86_64, cpus, memory);
	CU_ASSERT_EQUAL_FATAL(err, -EIO);
	CU_ASSERT_EQUAL(the_vm.fd, 0);
	CU_ASSERT_EQUAL(the_vm.vcpus, NULL);

	err = kvm_vm_create(&vm_test_opts, &the_vm, VM_MODE_X86_64, cpus, memory);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT(0 < the_vm.fd);
	CU_ASSERT_PTR_NOT_NULL_FATAL(the_vm.vcpus);

	kvm_vm_destroy(&the_vm);

	//TODO test for -ENOMEM
}

void test_kvm_vm_vcpu_count() {
	struct kvm_vm the_vm;
	the_vm.vcpus = NULL;

	int cpus = kvm_vm_vcpu_count(&the_vm);
	CU_ASSERT_EQUAL(cpus, 0);

	the_vm.vcpus = malloc(sizeof(struct vcpu_list));
	the_vm.vcpus->vcpu = NULL;
	the_vm.vcpus->next = NULL;

	cpus = kvm_vm_vcpu_count(&the_vm);
	CU_ASSERT_EQUAL(cpus, 0);

	the_vm.vcpus->vcpu = malloc(sizeof(struct kvm_vcpu));

	cpus = kvm_vm_vcpu_count(&the_vm);
	CU_ASSERT_EQUAL(cpus, 1);

	the_vm.vcpus->next = malloc(sizeof(struct vcpu_list));

	cpus = kvm_vm_vcpu_count(&the_vm);
	CU_ASSERT_EQUAL(cpus, 1);

	the_vm.vcpus->next->vcpu = malloc(sizeof(struct kvm_vcpu));

	cpus = kvm_vm_vcpu_count(&the_vm);
	CU_ASSERT_EQUAL(cpus, 2);

	the_vm.vcpus->next->next = malloc(sizeof(struct vcpu_list));
	the_vm.vcpus->next->next->vcpu = malloc(sizeof(struct kvm_vcpu));

	cpus = kvm_vm_vcpu_count(&the_vm);
	CU_ASSERT_EQUAL(cpus, 3);
}
