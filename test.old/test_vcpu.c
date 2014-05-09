#include <check.h>

#include <errno.h>
#include <stdlib.h>
#include <stropts.h>

#include <elkvm.h>
#include <vcpu.h>

struct elkvm_opts vcpu_test_opts;
struct kvm_vm vcpu_test_vm;
int num_vcpus = 0;


void setup() {
	int err = elkvm_init(&vcpu_test_opts, 0, NULL, NULL);
	vcpu_test_vm.fd = ioctl(vcpu_test_opts.fd, KVM_CREATE_VM, 0);
	vcpu_test_vm.vcpus = NULL;
}

void teardown() {
	kvm_vm_destroy(&vcpu_test_vm);
	elkvm_cleanup(&vcpu_test_opts);
}

START_TEST(test_kvm_vcpu_create_invalid) {
	struct kvm_vm invalid_vm;
	invalid_vm.fd = 0;
	invalid_vm.vcpus = NULL;

	/* an invalid vm, no vcpu should be created */
	int err = kvm_vcpu_create(&invalid_vm, VM_MODE_X86_64);
	ck_assert_int_eq(err, -EIO);
	ck_assert_ptr_eq(invalid_vm.vcpus, NULL);
}
END_TEST

START_TEST(test_kvm_vcpu_create_valid) {
	/* create a first vcpu */
	int err = kvm_vcpu_create(&vcpu_test_vm, VM_MODE_X86_64);
	ck_assert_int_eq(err, 0);
	ck_assert_ptr_ne(vcpu_test_vm.vcpus, NULL);
	ck_assert_ptr_ne(vcpu_test_vm.vcpus->vcpu, NULL);

	struct kvm_vcpu *vcpu = vcpu_test_vm.vcpus->vcpu;
	ck_assert_int_ne(vcpu->fd, 0);
	ck_assert_int_eq(vcpu->regs.rip, 0);
	ck_assert_int_eq(vcpu->regs.rax, 0);
	ck_assert_int_eq(vcpu->regs.rbx, 0);
	ck_assert_int_eq(vcpu->regs.rcx, 0);
	ck_assert_int_eq(vcpu->regs.rdx, 0);
	ck_assert_int_ne((vcpu->sregs.cr0 & (VCPU_CR0_FLAG_PAGING | VCPU_CR0_FLAG_PROTECTED)), 0);
	ck_assert_int_ne((vcpu->sregs.cr4 & VCPU_CR4_FLAG_PAE), 0);
	ck_assert_int_ne((vcpu->sregs.efer & VCPU_EFER_FLAG_LME), 0);

	/* now destroy the vcpu */
	err = kvm_vcpu_destroy(&vcpu_test_vm, vcpu_test_vm.vcpus->vcpu);
	ck_assert_int_eq(err, 0);

}
END_TEST

START_TEST(test_kvm_vcpu_get_regs) {
	struct kvm_vcpu invalid_vcpu;
	memset(&invalid_vcpu, 0, sizeof(struct kvm_vcpu));

	int err = kvm_vcpu_get_regs(&invalid_vcpu);
	ck_assert_int_eq(err, -EIO);
	ck_assert_int_eq(invalid_vcpu.regs.rip, 0);
	ck_assert_int_eq(invalid_vcpu.regs.rax, 0);
	ck_assert_int_eq(invalid_vcpu.regs.rbx, 0);
	ck_assert_int_eq(invalid_vcpu.regs.rcx, 0);
	ck_assert_int_eq(invalid_vcpu.regs.rdx, 0);
	ck_assert_int_eq(invalid_vcpu.sregs.cr0, 0);

	err = kvm_vcpu_create(&vcpu_test_vm, VM_MODE_X86_64);
	ck_assert_int_eq(err, 0);
	ck_assert_ptr_ne(vcpu_test_vm.vcpus, NULL);
	ck_assert_ptr_ne(vcpu_test_vm.vcpus->vcpu, NULL);

	struct kvm_vcpu *valid_vcpu = vcpu_test_vm.vcpus->vcpu;
	ck_assert(valid_vcpu->fd > 0);

	err = kvm_vcpu_get_regs(valid_vcpu);
	ck_assert_int_eq(err, 0);
	ck_assert_int_eq(valid_vcpu->regs.rip, 0);
	ck_assert_int_eq(valid_vcpu->regs.rax, 0);
	ck_assert_int_eq(valid_vcpu->regs.rbx, 0);
	ck_assert_int_eq(valid_vcpu->regs.rcx, 0);
	ck_assert_int_eq(valid_vcpu->regs.rdx, 0);
	ck_assert_int_ne(valid_vcpu->sregs.cr0 & (VCPU_CR0_FLAG_PAGING | VCPU_CR0_FLAG_PROTECTED), 0);
	ck_assert_int_ne(valid_vcpu->sregs.efer & VCPU_EFER_FLAG_LME, 0);

	kvm_vcpu_destroy(&vcpu_test_vm, valid_vcpu);
}
END_TEST

START_TEST(test_kvm_vcpu_set_regs) {
	struct kvm_vcpu invalid_vcpu;
	memset(&invalid_vcpu, 0, sizeof(struct kvm_vcpu));

	int err = kvm_vcpu_set_regs(&invalid_vcpu);
	ck_assert_int_eq(err, -EIO);

	err = kvm_vcpu_create(&vcpu_test_vm, VM_MODE_X86_64);
	ck_assert_int_eq(err, 0);
	struct kvm_vcpu *valid_vcpu = vcpu_test_vm.vcpus->vcpu;
	ck_assert(valid_vcpu->fd > 0);

	valid_vcpu->regs.rip = 0x1234;
	valid_vcpu->regs.rcx = 0x5678;
	valid_vcpu->sregs.cr2 = 0x9101;
	err = kvm_vcpu_set_regs(valid_vcpu);
	ck_assert_int_eq(err, 0);

	err = kvm_vcpu_get_regs(valid_vcpu);
	ck_assert_int_eq(err, 0);

	ck_assert_int_eq(valid_vcpu->regs.rip, 0x1234);
	ck_assert_int_eq(valid_vcpu->regs.rcx, 0x5678);
	ck_assert_int_eq(valid_vcpu->sregs.cr2, 0x9101);

	err = kvm_vcpu_destroy(&vcpu_test_vm, valid_vcpu);
	ck_assert_int_eq(err, 0);
}
END_TEST

START_TEST(test_kvm_vcpu_destroy) {

	/* delete an invalid element */
	struct kvm_vcpu invalid_vcpu;
	memset(&invalid_vcpu, 0, sizeof(struct kvm_vcpu));

	int err = kvm_vcpu_destroy(&vcpu_test_vm, &invalid_vcpu);
	ck_assert_int_eq(err, -1);

	/* delete the only element */
	struct kvm_vcpu *vcpu = malloc(sizeof(struct kvm_vcpu));
	err = kvm_vcpu_add_tail(&vcpu_test_vm, vcpu);
	ck_assert_int_eq(err, 0);

	err = kvm_vcpu_destroy(&vcpu_test_vm, vcpu);
	ck_assert_int_eq(err, 0);

	/* delete the middle element */
	vcpu = malloc(sizeof(struct kvm_vcpu));
	err = kvm_vcpu_add_tail(&vcpu_test_vm, vcpu);
	ck_assert_int_eq(err, 0);
	struct kvm_vcpu *vcpu_1 = malloc(sizeof(struct kvm_vcpu));
	err = kvm_vcpu_add_tail(&vcpu_test_vm, vcpu_1);
	ck_assert_int_eq(err, 0);
	struct kvm_vcpu *vcpu_2 = malloc(sizeof(struct kvm_vcpu));
	err = kvm_vcpu_add_tail(&vcpu_test_vm, vcpu_2);
	ck_assert_int_eq(err, 0);
	err = kvm_vcpu_destroy(&vcpu_test_vm, vcpu_1);
	ck_assert_int_eq(err, 0);
	ck_assert_ptr_eq(vcpu, vcpu_test_vm.vcpus->vcpu);
	ck_assert_ptr_eq(vcpu_2, vcpu_test_vm.vcpus->next->vcpu);

	/* delete the first element of two */
	err = kvm_vcpu_destroy(&vcpu_test_vm, vcpu);
	ck_assert_int_eq(err, 0);
	ck_assert_ptr_eq(vcpu_2, vcpu_test_vm.vcpus->vcpu);

	/* delete the last element */
	err = kvm_vcpu_destroy(&vcpu_test_vm, vcpu_2);
	ck_assert_int_eq(err, 0);
	ck_assert_ptr_eq(vcpu_test_vm.vcpus, NULL);
}
END_TEST

START_TEST(test_kvm_vcpu_add_tail) {
	struct kvm_vm the_vm;
	memset(&the_vm, 0, sizeof(struct kvm_vm));

	struct kvm_vcpu vcpu_0;
	int err = kvm_vcpu_add_tail(&the_vm, &vcpu_0);
	ck_assert_int_eq(err, 0);
	ck_assert_ptr_ne(the_vm.vcpus, NULL);
	ck_assert_ptr_eq(the_vm.vcpus->vcpu, &vcpu_0);

	struct kvm_vcpu vcpu_1;
	err = kvm_vcpu_add_tail(&the_vm, &vcpu_1);
	ck_assert_int_eq(err, 0);
	ck_assert_ptr_eq(the_vm.vcpus->vcpu, &vcpu_0);
	ck_assert_ptr_eq(the_vm.vcpus->next->vcpu, &vcpu_1);

	struct kvm_vcpu vcpu_2;
	err = kvm_vcpu_add_tail(&the_vm, &vcpu_2);
	ck_assert_int_eq(err, 0);
	ck_assert_ptr_eq(the_vm.vcpus->vcpu, &vcpu_0);
	ck_assert_ptr_eq(the_vm.vcpus->next->vcpu, &vcpu_1);
	ck_assert_ptr_eq(the_vm.vcpus->next->next->vcpu, &vcpu_2);
}
END_TEST

START_TEST(test_kvm_vcpu_run) {
	ck_abort_msg("Test not implemented");
}
END_TEST

Suite *vcpu_suite() {
	Suite *s = suite_create("VCPU");

	TCase *tc_kvm_vcpu_create = tcase_create("kvm_vcpu_create");
	tcase_add_checked_fixture(tc_kvm_vcpu_create, setup, teardown);
	tcase_add_test(tc_kvm_vcpu_create, test_kvm_vcpu_create_invalid);
	tcase_add_test(tc_kvm_vcpu_create, test_kvm_vcpu_create_valid);
	suite_add_tcase(s, tc_kvm_vcpu_create);

	TCase *tc_kvm_vcpu_destroy = tcase_create("kvm_vcpu_destroy");
	tcase_add_test(tc_kvm_vcpu_destroy, test_kvm_vcpu_destroy);
	suite_add_tcase(s, tc_kvm_vcpu_destroy);

	TCase *tc_kvm_vcpu_add_tail = tcase_create("kvm_vcpu_add_tail");
	tcase_add_test(tc_kvm_vcpu_add_tail, test_kvm_vcpu_add_tail);
	suite_add_tcase(s, tc_kvm_vcpu_add_tail);

	TCase *tc_kvm_vcpu_get_regs = tcase_create("kvm_vcpu_get_regs");
	tcase_add_checked_fixture(tc_kvm_vcpu_get_regs, setup, teardown);
	tcase_add_test(tc_kvm_vcpu_get_regs, test_kvm_vcpu_get_regs);
	suite_add_tcase(s, tc_kvm_vcpu_get_regs);

	TCase *tc_kvm_vcpu_set_regs = tcase_create("kvm_vcpu_set_regs");
	tcase_add_checked_fixture(tc_kvm_vcpu_set_regs, setup, teardown);
	tcase_add_test(tc_kvm_vcpu_set_regs, test_kvm_vcpu_set_regs);
	suite_add_tcase(s, tc_kvm_vcpu_set_regs);

	TCase *tc_kvm_vcpu_run = tcase_create("kvm_vcpu_run");
	tcase_add_checked_fixture(tc_kvm_vcpu_run, setup, teardown);
	tcase_add_test(tc_kvm_vcpu_run, test_kvm_vcpu_run);
	suite_add_tcase(s, tc_kvm_vcpu_run);

	return s;
}
