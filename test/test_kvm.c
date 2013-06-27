#include <CUnit/Basic.h>

#include <kvm.h>

#include "test_kvm.h"

struct kvm_opts kvm_test_opts;

void test_kvm_init() {

	int err = kvm_init(&kvm_test_opts);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT(0 < kvm_test_opts.fd);
	CU_ASSERT(0 < kvm_test_opts.run_struct_size);

}

void test_kvm_cleanup() {
	int err = kvm_cleanup(&kvm_test_opts);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_EQUAL(kvm_test_opts.fd, 0);
	CU_ASSERT_EQUAL(kvm_test_opts.run_struct_size, 0);
}
