
#include <assert.h>
#include <check.h>

#include <elkvm.h>
#include <heap.h>
#include <region.h>

struct kvm_vm heap_vm;
struct elkvm_memory_region heap_region;

void setup_heap() {
  int rsize = 0x6000;
  int err = elkvm_region_setup(&heap_vm);
  assert(err == 0);
  err = elkvm_heap_initialize(&heap_vm, &heap_region, 0x1000);
  assert(err == 0);
}

void teardown_heap() {
  free(heap_vm.root_region->data->host_base_p);
  free(heap_vm.root_region);
}

START_TEST(test_initialize_heap) {
  struct kvm_vm vm;
  int size = 0x1000;

  int err = elkvm_heap_initialize(&vm, &heap_region, size);
  ck_assert_int_eq(err, 0);
  ck_assert_ptr_ne(vm.heap, NULL);
  ck_assert_ptr_eq(vm.heap->data, &heap_region);
  ck_assert_ptr_eq(vm.heap->next, NULL);
}
END_TEST

START_TEST(test_grow_heap_no_memresize) {
  int size = 0x4000;
  int err = elkvm_heap_grow(&heap_vm, size);
  ck_assert_int_eq(err, 0);
  ck_assert_ptr_ne(heap_vm.heap->next, NULL);
  ck_assert_ptr_ne(heap_vm.heap->next->data, NULL);
  ck_assert_ptr_eq(heap_vm.heap->next->data, &heap_region);

  struct elkvm_memory_region *r = heap_vm.heap->data;
  ck_assert_ptr_ne(r, NULL);
  ck_assert_int_ge(r->region_size, size);
}
END_TEST

START_TEST(test_grow_heap_memresize) {
  int size = 0x8000;
  int err = elkvm_heap_grow(&heap_vm, size);
  ck_assert_int_eq(err, 0);
  ck_assert_ptr_ne(heap_vm.heap->next, NULL);
  ck_assert_ptr_ne(heap_vm.heap->next->data, NULL);
  ck_assert_ptr_eq(heap_vm.heap->next->data, &heap_region);

  struct elkvm_memory_region *r = heap_vm.heap->data;
  ck_assert_ptr_ne(r, NULL);
  ck_assert_int_ge(r->region_size, size);
}
END_TEST

Suite *heap_suite() {
  Suite *s = suite_create("Heap");

  TCase *tc_heap_create = tcase_create("Heap Create");
  tcase_add_test(tc_heap_create, test_initialize_heap);
  suite_add_tcase(s, tc_heap_create);

  TCase *tc_heap_grow = tcase_create("Heap Grow");
  tcase_add_test(tc_heap_grow, test_grow_heap_no_memresize);
  tcase_add_test(tc_heap_grow, test_grow_heap_memresize);
  tcase_add_checked_fixture(tc_heap_grow, setup_heap, teardown_heap);
  suite_add_tcase(s, tc_heap_grow);

  return s;
}
