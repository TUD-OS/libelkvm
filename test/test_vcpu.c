#include <CUnit/Basic.h>

#include <stropts.h>

#include "test_vcpu.h"

#include <elkvm.h>
#include <vcpu.h>

struct kvm_opts vcpu_test_opts;
struct kvm_vm vcpu_test_vm;

int init_vcpu_suite() {
	int err = kvm_init(&vcpu_test_opts);
	if(err) {
		return err;
	}
	vcpu_test_vm.fd = ioctl(vcpu_test_opts.fd, KVM_CREATE_VM, 0);
	if(vcpu_test_vm.fd == 0) {
		return -1;
	}
	vcpu_test_vm.vcpus = NULL;
	return err;
}

int clean_vcpu_suite() {
	kvm_vm_destroy(&vcpu_test_vm);
	kvm_cleanup(&vcpu_test_opts);
	return 0;
}

void test_kvm_vcpu_create() {
	struct kvm_vm the_vm;
	the_vm.fd = 0;
	the_vm.vcpus = NULL;

	int err = kvm_vcpu_create(&the_vm, VM_MODE_X86_64);
	CU_ASSERT_EQUAL(err, -EIO);
	CU_ASSERT_PTR_NULL(the_vm.vcpus);

	/* create a first vcpu */
	err = kvm_vcpu_create(&vcpu_test_vm, VM_MODE_X86_64);
	CU_ASSERT_EQUAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(vcpu_test_vm.vcpus);
	CU_ASSERT_PTR_NOT_NULL_FATAL(vcpu_test_vm.vcpus->vcpu);
	struct kvm_vcpu *vcpu = vcpu_test_vm.vcpus->vcpu;
	CU_ASSERT_NOT_EQUAL(vcpu->fd, 0);
	err = kvm_vcpu_get_regs(vcpu);
	CU_ASSERT_EQUAL(err, 0);
	CU_ASSERT_EQUAL(vcpu->regs.rip, 0);
	CU_ASSERT_EQUAL(vcpu->regs.rax, 0);
	CU_ASSERT_EQUAL(vcpu->regs.rbx, 0);
	CU_ASSERT_EQUAL(vcpu->regs.rcx, 0);
	CU_ASSERT_EQUAL(vcpu->regs.rdx, 0);
	CU_ASSERT_NOT_EQUAL((vcpu->sregs.cr0 & (VCPU_CR0_FLAG_PAGING | VCPU_CR0_FLAG_PROTECTED)), 0);
	CU_ASSERT_NOT_EQUAL((vcpu->sregs.cr4 & VCPU_CR4_FLAG_PAE), 0);
	CU_ASSERT_NOT_EQUAL((vcpu->sregs.efer & VCPU_EFER_FLAG_LME), 0);

	/* and a second one */
	err = kvm_vcpu_create(&vcpu_test_vm, VM_MODE_X86_64);
	CU_ASSERT_EQUAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(vcpu_test_vm.vcpus->next);
	CU_ASSERT_PTR_NOT_NULL_FATAL(vcpu_test_vm.vcpus->next->vcpu);
	vcpu = vcpu_test_vm.vcpus->next->vcpu;
	CU_ASSERT_NOT_EQUAL(vcpu->fd, 0);
	err = kvm_vcpu_get_regs(vcpu);
	CU_ASSERT_EQUAL(err, 0);
	CU_ASSERT_EQUAL(vcpu->regs.rip, 0);
	CU_ASSERT_EQUAL(vcpu->regs.rax, 0);
	CU_ASSERT_EQUAL(vcpu->regs.rbx, 0);
	CU_ASSERT_EQUAL(vcpu->regs.rcx, 0);
	CU_ASSERT_EQUAL(vcpu->regs.rdx, 0);
	CU_ASSERT_NOT_EQUAL((vcpu->sregs.cr0 & (VCPU_CR0_FLAG_PAGING | VCPU_CR0_FLAG_PROTECTED)), 0);
	CU_ASSERT_NOT_EQUAL((vcpu->sregs.cr4 & VCPU_CR4_FLAG_PAE), 0);
	CU_ASSERT_NOT_EQUAL((vcpu->sregs.efer & VCPU_EFER_FLAG_LME), 0);

	/* now destroy the first one */
	err = kvm_vcpu_destroy(&vcpu_test_vm, vcpu_test_vm.vcpus->vcpu);
	CU_ASSERT_EQUAL(err, 0);

	/* and the second one */
	err = kvm_vcpu_destroy(&vcpu_test_vm, vcpu);
	CU_ASSERT_EQUAL(err, 0);
}

void test_kvm_vcpu_get_regs() {
	struct kvm_vcpu invalid_vcpu;
	memset(&invalid_vcpu, 0, sizeof(struct kvm_vcpu));

	int err = kvm_vcpu_get_regs(&invalid_vcpu);
	CU_ASSERT_EQUAL(err, -EIO);
	CU_ASSERT_EQUAL(invalid_vcpu.regs.rip, 0);
	CU_ASSERT_EQUAL(invalid_vcpu.regs.rax, 0);
	CU_ASSERT_EQUAL(invalid_vcpu.regs.rbx, 0);
	CU_ASSERT_EQUAL(invalid_vcpu.regs.rcx, 0);
	CU_ASSERT_EQUAL(invalid_vcpu.regs.rdx, 0);
	CU_ASSERT_EQUAL(invalid_vcpu.sregs.cr0, 0);

	err = kvm_vcpu_create(&vcpu_test_vm, VM_MODE_X86_64);
	CU_ASSERT_EQUAL(err, 0);

	struct kvm_vcpu *valid_vcpu = vcpu_test_vm.vcpus->vcpu;
	CU_ASSERT(valid_vcpu->fd > 0);

	err = kvm_vcpu_get_regs(valid_vcpu);
	CU_ASSERT_EQUAL(err, 0);
	CU_ASSERT_EQUAL(valid_vcpu->regs.rip, 0);
	CU_ASSERT_EQUAL(valid_vcpu->regs.rax, 0);
	CU_ASSERT_EQUAL(valid_vcpu->regs.rbx, 0);
	CU_ASSERT_EQUAL(valid_vcpu->regs.rcx, 0);
	CU_ASSERT_EQUAL(valid_vcpu->regs.rdx, 0);
	CU_ASSERT_NOT_EQUAL(valid_vcpu->sregs.cr0 & VCPU_CR0_FLAG_PAGING & VCPU_CR0_FLAG_PROTECTED, 0);
	CU_ASSERT_EQUAL(valid_vcpu->sregs.efer, VCPU_EFER_FLAG_LME);

	kvm_vcpu_destroy(&vcpu_test_vm, valid_vcpu);
}

void test_kvm_vcpu_set_regs() {
	CU_ASSERT(0);
}

