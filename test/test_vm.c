
#include <CUnit/Basic.h>
#include <linux/kvm.h>

#include <vm.h>

int init_vm_suite() {
	return 0;
}

int clean_vm_suite() {
	return 0;
}

void test_kvm_vm_create() {

	struct kvm_vm the_vm;
	int cpus = 1;
	int enough_memory = 256*1024*1024;
	int barely_enough_memory = 4*1024*1024 + 4*1024;

	int err = kvm_vm_create(&the_vm, VM_MODE_X86_64, cpus, memory);
	CU_ASSERT(0 == err);

	kvm_vm_destroy(&the_vm);

	err = kvm_vm_create(&the_vm, VM_MODE_X86_64, cpus, barely_enough_memory);
	CU_ASSERT(0 == err);

	kvm_vm_destroy(&the_vm);

	err = kvm_vm_create(&the_vm, VM_MODE_X86_64, cpus, barely_enough_memory -1);
	CU_ASSERT(0 > err);
}

int main() {
	CU_pSuite pSuite = NULL;

	if(CUE_SUCCESS != CU_initialize_registry()) {
		return CU_get_error();
	}

	pSuite = CU_add_suite("VM_Suite", init_vm_suite, clean_vm_suite);
	if(NULL == pSuite) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if((NULL == CU_add_test(pSuite, "Test kvm_vm_create()", test_kvm_vm_create))
		) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	CU_cleanup_registry();
	return CU_get_error();
}
