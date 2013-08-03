#include <gdt.h>

#include <check.h>
#include <errno.h>
#include <string.h>

struct elkvm_gdt_segment_descriptor *test_descr;

void setup_descriptor() {
	test_descr = malloc(sizeof(struct elkvm_gdt_segment_descriptor));
	memset(test_descr, 0, sizeof(struct elkvm_gdt_segment_descriptor));
}

void teardown_descriptor() {
	free(test_descr);
}

START_TEST(test_elkvm_gdt_create_segment_base_too_long) {

	int err = elkvm_gdt_create_segment_descriptor(test_descr,
		 	0x1FFFFF, 0xFFFFFFFF, 0x9A, 0x0);
	ck_assert_int_eq(err, -EINVAL);

}
END_TEST

START_TEST(test_elkvm_gdt_create_segment_valid) {

	int err = elkvm_gdt_create_segment_descriptor(test_descr,
		 0x0, 0xFFFFFFFF, 0x9A, 0x0);
	ck_assert_int_eq(err, 0);

}
END_TEST

Suite *gdt_suite() {
	Suite *s = suite_create("Global Descriptor Table");

	TCase *tc_create_segment = tcase_create("Create Segments");
	tcase_add_test(tc_create_segment, test_elkvm_gdt_create_segment_base_too_long);
	tcase_add_test(tc_create_segment, test_elkvm_gdt_create_segment_valid);
	tcase_add_checked_fixture(tc_create_segment, 
			setup_descriptor, teardown_descriptor);
	suite_add_tcase(s, tc_create_segment);

	return s;
}
