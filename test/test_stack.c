#include <assert.h>
#include <check.h>
#include <stdlib.h>

#include <elkvm.h>
#include <stack.h>
#include <vcpu.h>

struct kvm_opts stack_opts;
struct kvm_vm stack_vm;

void setup_stack() {
	int err = kvm_init(&stack_opts);
	assert(err == 0);
	err = kvm_vm_create(&stack_opts, &stack_vm, VM_MODE_X86_64, 1, 0);
	assert(err == 0);
}

void teardown_stack() {
	kvm_vm_destroy(&stack_vm);
}

START_TEST(test_pop_stack) {

	struct kvm_vcpu *vcpu = stack_vm.vcpus->vcpu;

	int err = kvm_vcpu_get_regs(vcpu);
	ck_assert_int_eq(err, 0);

	vcpu->regs.rsp = 0x2000;

	err = kvm_vcpu_set_regs(vcpu);
	ck_assert_int_eq(err, 0);

	uint16_t *host_mem_p = (uint16_t *)stack_vm.pager.system_chunk.userspace_addr;
	uint16_t magic_val = 0x42;

	*host_mem_p = magic_val;

	kvm_pager_create_mapping(&stack_vm.pager, host_mem_p, vcpu->regs.rsp);

	uint16_t popped_val = pop_stack(&stack_vm, vcpu);
	ck_assert_int_eq(popped_val, magic_val);

	//kvm_pager_cleanup(&vm.pager);
}
END_TEST

Suite *stack_suite() {
	Suite *s = suite_create("Stack");

	TCase *tc_pop = tcase_create("pop");
	tcase_add_checked_fixture(tc_pop, setup_stack, teardown_stack);
	tcase_add_test(tc_pop, test_pop_stack);
	suite_add_tcase(s, tc_pop);

	return s;
}
