#include <CUnit/Basic.h>

#include <elkvm.h>
#include <pager.h>

#include "test_pager.h"

struct kvm_opts pager_test_opts;

int init_pager_suite() {
	int err = kvm_init(&pager_test_opts);
	return err;
}

int clean_pager_suite() {
	kvm_cleanup(&pager_test_opts);
	return 0;
}

void test_kvm_pager_initialize() {
	CU_ASSERT(0);
}

void test_kvm_pager_create_mem_chunk() {
	CU_ASSERT(0);
}
