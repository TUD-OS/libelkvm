
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
	the_vm.fd = 0;
	the_vm.vcpus = NULL;
	int cpus = 1;
	int memory = 256*1024*1024;

	struct kvm_opts uninitialized_opts;
	uninitialized_opts.fd = 0;
	int err = kvm_vm_create(&uninitialized_opts, &the_vm, VM_MODE_X86_64, cpus, memory);
	CU_ASSERT(err == -EIO);
	CU_ASSERT(the_vm.fd == 0);
	CU_ASSERT(the_vm.vcpus == NULL);

	err = kvm_vm_create(&vm_test_opts, &the_vm, VM_MODE_X86_64, cpus, memory);
	CU_ASSERT(0 == err);
	CU_ASSERT(0 < the_vm.fd);
	CU_ASSERT(NULL != the_vm.vcpus);

	kvm_vm_destroy(&the_vm);

	//TODO test for -ENOMEM
}

