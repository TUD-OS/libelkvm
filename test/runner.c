#include <check.h>
#include <stdlib.h>

#include "test_kvm.h"
#include "test_vm.h"

extern Suite *elfloader_suite();
extern Suite *gdt_suite();
extern Suite *stack_suite();
extern Suite *syscall_suite();
extern Suite *pager_suite();
extern Suite *region_suite();
extern Suite *vcpu_suite();

int main() {
	int number_failed = 0;

	Suite *s = vcpu_suite();
	SRunner *sr = srunner_create(s);
	srunner_add_suite(sr, elfloader_suite());
	srunner_add_suite(sr, vm_suite());
	srunner_add_suite(sr, kvm_suite());
	srunner_add_suite(sr, pager_suite());
	srunner_add_suite(sr, stack_suite());
	srunner_add_suite(sr, gdt_suite());
	srunner_add_suite(sr, syscall_suite());
	srunner_add_suite(sr, region_suite());
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

