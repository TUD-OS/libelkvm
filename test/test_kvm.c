#include <check.h>

#include <kvm.h>

#include "test_kvm.h"

struct kvm_opts kvm_test_opts;

START_TEST(test_kvm_init) {

	int err = kvm_init(&kvm_test_opts);
	ck_assert_int_eq(err, 0);
	ck_assert_int_gt(kvm_test_opts.fd, 0);
	ck_assert_int_gt(kvm_test_opts.run_struct_size, 0);

}
END_TEST

START_TEST(test_kvm_cleanup) {
	int err = kvm_cleanup(&kvm_test_opts);
	ck_assert_int_eq(err, 0);
	ck_assert_int_eq(kvm_test_opts.fd, 0);
	ck_assert_int_eq(kvm_test_opts.run_struct_size, 0);
}
END_TEST

Suite *kvm_suite() {
	Suite *s = suite_create("KVM");

	TCase *tc_init = tcase_create("init");
	tcase_add_test(tc_init, test_kvm_init);
	tcase_add_test(tc_init, test_kvm_cleanup);
	suite_add_tcase(s, tc_init);

	return s;
}
