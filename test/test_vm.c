
#include <CUnit/Basic.h>

#include <kvm.h>
#include <elkvm.h>

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
	int cpus = 1;
	int enough_memory = 256*1024*1024;
	int barely_enough_memory = 4*1024*1024 + 4*1024;

	int err = kvm_vm_create(&vm_test_opts, &the_vm, VM_MODE_X86_64, cpus, enough_memory);
	CU_ASSERT(0 == err);
	CU_ASSERT(0 < the_vm.fd);
	CU_ASSERT(NULL != the_vm.vcpu);

	kvm_vm_destroy(&the_vm);

	err = kvm_vm_create(&vm_test_opts, &the_vm, VM_MODE_X86_64, cpus, barely_enough_memory);
	CU_ASSERT(0 == err);
	CU_ASSERT(0 < the_vm.fd);
	CU_ASSERT(NULL != the_vm.vcpu);

	kvm_vm_destroy(&the_vm);

	err = kvm_vm_create(&vm_test_opts, &the_vm, VM_MODE_X86_64, cpus, barely_enough_memory -1);
	CU_ASSERT(0 > err);
	CU_ASSERT(0 == the_vm.fd);
	CU_ASSERT(NULL == the_vm.vcpu);

	//TODO test for -ENOMEM
}

