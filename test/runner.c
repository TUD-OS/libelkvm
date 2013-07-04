#include <check.h>
#include <stdlib.h>

#include "test_kvm.h"
#include "test_pager.h"
#include "test_vm.h"

extern Suite *vcpu_suite();

int main() {
	int number_failed = 0;

	Suite *s = vcpu_suite();
	SRunner *sr = srunner_create(s);
	srunner_add_suite(sr, vm_suite());
	srunner_add_suite(sr, kvm_suite());
	srunner_add_suite(sr, pager_suite());
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

