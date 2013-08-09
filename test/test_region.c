#include <check.h>

#include <elkvm.h>
#include <region.h>

struct kvm_vm region_vm;

void setup_region() {
	int err = posix_memalign(&region_vm.root_region.host_base_p, 0x1000, 0x400000);
	assert(err == 0);

	region_vm.root_region.guest_virtual = 0x0;
	region_vm.root_region.region_size = 0x400000;
	region_vm.root_region.grows_downward = 0;
	region_vm.root_region.used = 0;
	region_vm.root_region.lc = NULL;
	region_vm.root_region.rc = NULL;

}

void setup_region_tree() {
	int err = posix_memalign(&region_vm.root_region.host_base_p, 0x1000, 0x400000);
	assert(err == 0);

	region_vm.root_region.guest_virtual = 0x0;
	region_vm.root_region.region_size = 0x400000;
	region_vm.root_region.grows_downward = 0;
	region_vm.root_region.used = 1;

	struct elkvm_memory_region *lc = malloc(sizeof(struct elkvm_memory_region));
	region_vm.root_region.lc = lc;
	lc->guest_virtual = 0x0;
	lc->host_base_p = region_vm.root_region.host_base_p;
	lc->region_size = region_vm.root_region.region_size / 2;
	lc->used = 0;
	lc->lc = lc->rc = NULL;
	region_vm.root_region.lc = lc;

	struct elkvm_memory_region *rc = malloc(sizeof(struct elkvm_memory_region));
	region_vm.root_region.rc = rc;
	rc->guest_virtual = 0x0;
	rc->host_base_p = region_vm.root_region.host_base_p + lc->region_size;
	rc->region_size = region_vm.root_region.region_size / 2;
	rc->used = 0;
	rc->lc = rc->rc = NULL;
	region_vm.root_region.rc = rc;
}

void teardown_region() {
	free(region_vm.root_region.host_base_p);
}

void teardown_region_tree() {
	free(region_vm.root_region.lc);
	free(region_vm.root_region.rc);
	free(region_vm.root_region.host_base_p);
}

START_TEST(test_region_find_root) {
	region_vm.root_region.used = 0;

	struct elkvm_memory_region *r = elkvm_region_find(&region_vm.root_region,
			region_vm.root_region.region_size);
	ck_assert_ptr_eq(r, &region_vm.root_region);
}
END_TEST

START_TEST(test_region_find_left) {
	region_vm.root_region.rc->used = 1;

	struct elkvm_memory_region *region = elkvm_region_find(&region_vm.root_region, region_vm.root_region.region_size / 2);
	ck_assert_ptr_eq(region, region_vm.root_region.lc);
}
END_TEST

START_TEST(test_region_find_right) {
	region_vm.root_region.lc->used = 1;

	struct elkvm_memory_region *region = elkvm_region_find(&region_vm.root_region, region_vm.root_region.region_size / 2);
	ck_assert_ptr_eq(region, region_vm.root_region.rc);
}
END_TEST

START_TEST(test_region_find_smaller) {
	uint64_t size = region_vm.root_region.region_size / 4;
	struct elkvm_memory_region *region = elkvm_region_find(&region_vm.root_region, size);
	ck_assert_ptr_eq(region, region_vm.root_region.lc->lc);
	ck_assert_int_eq(region->region_size, size);

	free(region);
}
END_TEST

START_TEST(test_region_find_full) {
	region_vm.root_region.lc->used = 1;
	region_vm.root_region.rc->used = 1;

	struct elkvm_memory_region *region = elkvm_region_find(&region_vm.root_region, 0x1000);
	ck_assert_ptr_eq(region, NULL);
	
}
END_TEST

START_TEST(test_region_find_different_size) {
	uint64_t size = (region_vm.root_region.region_size / 2) - 0x1000;
	struct elkvm_memory_region *region = elkvm_region_find(&region_vm.root_region, size);
	ck_assert_ptr_eq(region, region_vm.root_region.lc);
}
END_TEST

START_TEST(test_region_split_invalid) {
	region_vm.root_region.used = 1;
	int err = elkvm_region_split(&region_vm.root_region);
	ck_assert_int_eq(err, -1);
	ck_assert_ptr_eq(region_vm.root_region.lc, NULL);
	ck_assert_ptr_eq(region_vm.root_region.rc, NULL);
}
END_TEST

START_TEST(test_region_split) {
	int err = elkvm_region_split(&region_vm.root_region);
	ck_assert_int_eq(err, 0);
	ck_assert_int_eq(region_vm.root_region.used, 1);
	ck_assert_ptr_ne(region_vm.root_region.lc, NULL);
	ck_assert_ptr_ne(region_vm.root_region.rc, NULL);

	struct elkvm_memory_region *child = region_vm.root_region.lc;
	ck_assert_int_eq(child->used, 0);
	ck_assert_int_eq(child->region_size, region_vm.root_region.region_size / 2);
	ck_assert_ptr_eq(child->host_base_p, region_vm.root_region.host_base_p);
	ck_assert_ptr_eq(child->lc, NULL);
	ck_assert_ptr_eq(child->rc, NULL);

	child = region_vm.root_region.rc;
	ck_assert_int_eq(child->used, 0);
	ck_assert_int_eq(child->region_size, region_vm.root_region.region_size / 2);
	ck_assert_ptr_eq(child->host_base_p,
			region_vm.root_region.host_base_p + child->region_size);
	ck_assert_ptr_eq(child->lc, NULL);
	ck_assert_ptr_eq(child->rc, NULL);
}
END_TEST

START_TEST(test_region_create_full_size) {
	struct elkvm_memory_region *new_region;
	new_region = elkvm_region_create(&region_vm, region_vm.root_region.region_size);
	ck_assert_ptr_eq(new_region, &region_vm.root_region);
	ck_assert_int_eq(region_vm.root_region.used, 1);
	ck_assert_ptr_eq(region_vm.root_region.lc, NULL);
	ck_assert_ptr_eq(region_vm.root_region.rc, NULL);
}
END_TEST

START_TEST(test_region_create_quarter_size) {
	struct elkvm_memory_region *new_region;
	new_region = elkvm_region_create(&region_vm, region_vm.root_region.region_size / 4);
	ck_assert_ptr_ne(new_region, &region_vm.root_region);
	ck_assert_int_eq(region_vm.root_region.used, 1);
	ck_assert_ptr_ne(region_vm.root_region.lc, NULL);
	ck_assert_ptr_ne(region_vm.root_region.rc, NULL);

	struct elkvm_memory_region *lc = region_vm.root_region.lc;
	ck_assert_ptr_ne(new_region, lc);
	ck_assert_int_eq(lc->used, 1);
	ck_assert_ptr_ne(lc->lc, NULL);
	ck_assert_ptr_ne(lc->rc, NULL);

	lc = lc->lc;
	ck_assert_ptr_eq(new_region, lc);
	ck_assert_int_eq(lc->used, 1);
	ck_assert_ptr_eq(lc->lc, NULL);
	ck_assert_ptr_eq(lc->rc, NULL);
}
END_TEST

START_TEST(test_region_create_different_size) {
	struct elkvm_memory_region *new_region;
	uint64_t size = (region_vm.root_region.region_size / 4) - 0x10000;

	new_region = elkvm_region_create(&region_vm, size);
	ck_assert_ptr_ne(new_region, &region_vm.root_region);
	ck_assert_int_eq(region_vm.root_region.used, 1);
	ck_assert_ptr_ne(region_vm.root_region.lc, NULL);
	ck_assert_ptr_ne(region_vm.root_region.rc, NULL);

	struct elkvm_memory_region *lc = region_vm.root_region.lc;
	ck_assert_ptr_ne(new_region, lc);
	ck_assert_int_eq(lc->used, 1);
	ck_assert_ptr_ne(lc->lc, NULL);
	ck_assert_ptr_ne(lc->rc, NULL);

	lc = lc->lc;
	ck_assert_ptr_eq(new_region, lc);
	ck_assert_int_eq(lc->used, 1);
	ck_assert_ptr_eq(lc->lc, NULL);
	ck_assert_ptr_eq(lc->rc, NULL);

}
END_TEST

START_TEST(test_region_create_too_large) {
	struct elkvm_memory_region *new_region;

	new_region = elkvm_region_create(&region_vm, region_vm.root_region.region_size + 1);
	ck_assert_ptr_eq(new_region, NULL);

}
END_TEST

Suite *region_suite() {
	Suite *s = suite_create("Dynamic Region Manager");

	TCase *tc_region_find = tcase_create("Region Find");
	tcase_add_test(tc_region_find, test_region_find_root);
	tcase_add_test(tc_region_find, test_region_find_left);
	tcase_add_test(tc_region_find, test_region_find_right);
	tcase_add_test(tc_region_find, test_region_find_smaller);
	tcase_add_test(tc_region_find, test_region_find_full);
	tcase_add_test(tc_region_find, test_region_find_different_size);
	tcase_add_checked_fixture(tc_region_find, setup_region_tree, teardown_region_tree);
	suite_add_tcase(s, tc_region_find);

	TCase *tc_region_split = tcase_create("Region Split");
	tcase_add_test(tc_region_split, test_region_split_invalid);
	tcase_add_test(tc_region_split, test_region_split);
	tcase_add_checked_fixture(tc_region_split, setup_region, teardown_region);
	suite_add_tcase(s, tc_region_split);

	TCase *tc_region_create = tcase_create("Region Create");
	tcase_add_test(tc_region_create, test_region_create_full_size);
	tcase_add_test(tc_region_create, test_region_create_quarter_size);
	tcase_add_test(tc_region_create, test_region_create_different_size);
	tcase_add_test(tc_region_create, test_region_create_too_large);
	tcase_add_checked_fixture(tc_region_create, setup_region, teardown_region);
	suite_add_tcase(s, tc_region_create);


	return s;
}
