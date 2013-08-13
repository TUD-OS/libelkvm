#include <assert.h>
#include <check.h>
#include <stdlib.h>

#include <elkvm.h>
#include <stack.h>
#include <vcpu.h>

struct elkvm_opts stack_opts;
struct kvm_vm stack_vm;

void setup_stack() {
	int err = elkvm_init(&stack_opts, 0, NULL, NULL);
	assert(err == 0);
	err = kvm_vm_create(&stack_opts, &stack_vm, VM_MODE_X86_64, 1, 0, NULL);
	assert(err == 0);

	stack_vm.vcpus->vcpu->regs.rsp = 0x2000;
	err = kvm_vcpu_set_regs(stack_vm.vcpus->vcpu);
	assert(err == 0);
}

void teardown_stack() {
	kvm_vm_destroy(&stack_vm);
}

START_TEST(test_push_stack) {
	struct kvm_vcpu *vcpu = stack_vm.vcpus->vcpu;

	//TODO initialize teh stack

	int err = kvm_vcpu_get_regs(vcpu);
	ck_assert_int_eq(err, 0);

	vcpu->regs.rsp = 0x1000;
	uint64_t old_rsp = vcpu->regs.rsp;

	err = kvm_vcpu_set_regs(vcpu);
	ck_assert_int_eq(err, 0);
	void *host_p = (void *)stack_vm.pager.system_chunk.userspace_addr + 0x1000;
	
	err = kvm_pager_create_mapping(&stack_vm.pager, host_p, vcpu->regs.rsp - 0x1000);
	ck_assert_int_eq(err, 0);
	
	uint16_t magic_val = 0x42;
	err = push_stack(&stack_vm, vcpu, magic_val);
	ck_assert_int_eq(err, 0);

	err = kvm_vcpu_get_regs(vcpu);
	ck_assert_int_eq(err, 0);
	ck_assert_uint_eq(vcpu->regs.rsp, old_rsp - 0x10);

	uint16_t *host_sp = (uint16_t *)kvm_pager_get_host_p(&stack_vm.pager, 
			vcpu->regs.rsp);
	ck_assert_uint_eq(*host_sp, magic_val);
}
END_TEST

START_TEST(test_push_stack_new_page) {
	ck_abort_msg("Test not implemented");
}
END_TEST

START_TEST(test_pop_stack) {

	struct kvm_vcpu *vcpu = stack_vm.vcpus->vcpu;

	int err = kvm_vcpu_get_regs(vcpu);
	ck_assert_int_eq(err, 0);

	uint16_t *host_mem_p = (uint16_t *)stack_vm.pager.system_chunk.userspace_addr;
	uint16_t magic_val = 0x42;

	*host_mem_p = magic_val;

	kvm_pager_create_mapping(&stack_vm.pager, host_mem_p, vcpu->regs.rsp);

	uint64_t old_rsp = vcpu->regs.rsp;
	uint16_t popped_val = pop_stack(&stack_vm, vcpu);
	ck_assert_int_eq(popped_val, magic_val);

	//check that stack pointer has changed!

	err = kvm_vcpu_get_regs(vcpu);
	ck_assert_int_eq(err, 0);

	ck_assert_uint_eq(vcpu->regs.rsp, old_rsp + 0x10);

	//kvm_pager_cleanup(&vm.pager);
}
END_TEST

Suite *stack_suite() {
	Suite *s = suite_create("Stack");

	TCase *tc_pop = tcase_create("Push / Pop");
	tcase_add_checked_fixture(tc_pop, setup_stack, teardown_stack);
	tcase_add_test(tc_pop, test_pop_stack);
	tcase_add_test(tc_pop, test_push_stack);
	tcase_add_test(tc_pop, test_push_stack_new_page);
	suite_add_tcase(s, tc_pop);

	return s;
}
