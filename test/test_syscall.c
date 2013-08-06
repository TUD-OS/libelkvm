
#include <check.h>

void syscall_setup() {
}

void syscall_teardown() {
}

START_TEST(test_handle_syscall) {
	ck_abort_msg("Syscall handler Test not implemented");
}
END_TEST

START_TEST(test_handle_tf) {
	ck_abort_msg("TF handler Test not implemented");
}
END_TEST

Suite *syscall_suite() {
	Suite *s = suite_create("Syscall");

	TCase *tc_handle_vm_shutdown = tcase_create("elkvm_handle_vcpu_shutdown");
	tcase_add_checked_fixture(tc_handle_vm_shutdown, syscall_setup, syscall_teardown);
	tcase_add_test(tc_handle_vm_shutdown, test_handle_tf);
	tcase_add_test(tc_handle_vm_shutdown, test_handle_syscall);
	suite_add_tcase(s, tc_handle_vm_shutdown);

	return s;
}
