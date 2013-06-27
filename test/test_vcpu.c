#include <CUnit/Basic.h>

#include <stdlib.h>
#include <stropts.h>

#include "test_vcpu.h"

#include <elkvm.h>
#include <vcpu.h>

struct kvm_opts vcpu_test_opts;
int num_vcpus = 0;

int init_vcpu_suite() {
	int err = kvm_init(&vcpu_test_opts);
	return err;
}

int clean_vcpu_suite() {
	kvm_cleanup(&vcpu_test_opts);
	return 0;
}

struct kvm_vm *init_test_vm() {
	struct kvm_vm *vm = malloc(sizeof(struct kvm_vm));
	CU_ASSERT_PTR_NOT_NULL_FATAL(vm);

	vm->fd = ioctl(vcpu_test_opts.fd, KVM_CREATE_VM, 0);
	if(vm->fd <= 0) {
		printf("KVM fd: %i VM fd: %i Errno: %i (%s)\n", vcpu_test_opts.fd, vm->fd, errno, strerror(errno));
		free(vm);
		CU_FAIL_FATAL("could not get valid VM");
		return NULL;
	}
	vm->vcpus = NULL;
	return vm;
}

void test_kvm_vcpu_create() {
	struct kvm_vm invalid_vm;
	invalid_vm.fd = 0;
	invalid_vm.vcpus = NULL;

	/* an invalid vm, no vcpu should be created */
	int err = kvm_vcpu_create(&invalid_vm, VM_MODE_X86_64);
	CU_ASSERT_EQUAL(err, -EIO);
	CU_ASSERT_PTR_NULL(invalid_vm.vcpus);

	struct kvm_vm *valid_vm = init_test_vm();
	/* create a first vcpu */
	CU_ASSERT_FATAL(valid_vm->vcpus == NULL || valid_vm->vcpus->vcpu == NULL);
	err = kvm_vcpu_create(valid_vm, VM_MODE_X86_64);
	CU_ASSERT_EQUAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(valid_vm->vcpus);
	CU_ASSERT_PTR_NOT_NULL_FATAL(valid_vm->vcpus->vcpu);

	struct kvm_vcpu *vcpu = valid_vm->vcpus->vcpu;
	CU_ASSERT_NOT_EQUAL(vcpu->fd, 0);
	CU_ASSERT_EQUAL(vcpu->regs.rip, 0);
	CU_ASSERT_EQUAL(vcpu->regs.rax, 0);
	CU_ASSERT_EQUAL(vcpu->regs.rbx, 0);
	CU_ASSERT_EQUAL(vcpu->regs.rcx, 0);
	CU_ASSERT_EQUAL(vcpu->regs.rdx, 0);
	CU_ASSERT_NOT_EQUAL((vcpu->sregs.cr0 & (VCPU_CR0_FLAG_PAGING | VCPU_CR0_FLAG_PROTECTED)), 0);
	CU_ASSERT_NOT_EQUAL((vcpu->sregs.cr4 & VCPU_CR4_FLAG_PAE), 0);
	CU_ASSERT_NOT_EQUAL((vcpu->sregs.efer & VCPU_EFER_FLAG_LME), 0);

	/* now destroy the vcpu */
	err = kvm_vcpu_destroy(valid_vm, valid_vm->vcpus->vcpu);
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

	struct kvm_vm *valid_vm = init_test_vm();
	err = kvm_vcpu_create(valid_vm, VM_MODE_X86_64);
	CU_ASSERT_EQUAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(valid_vm->vcpus);
	CU_ASSERT_PTR_NOT_NULL_FATAL(valid_vm->vcpus->vcpu);

	struct kvm_vcpu *valid_vcpu = valid_vm->vcpus->vcpu;
	CU_ASSERT(valid_vcpu->fd > 0);

	err = kvm_vcpu_get_regs(valid_vcpu);
	CU_ASSERT_EQUAL(err, 0);
	CU_ASSERT_EQUAL(valid_vcpu->regs.rip, 0);
	CU_ASSERT_EQUAL(valid_vcpu->regs.rax, 0);
	CU_ASSERT_EQUAL(valid_vcpu->regs.rbx, 0);
	CU_ASSERT_EQUAL(valid_vcpu->regs.rcx, 0);
	CU_ASSERT_EQUAL(valid_vcpu->regs.rdx, 0);
	CU_ASSERT_NOT_EQUAL(valid_vcpu->sregs.cr0 & (VCPU_CR0_FLAG_PAGING | VCPU_CR0_FLAG_PROTECTED), 0);
	CU_ASSERT_NOT_EQUAL(valid_vcpu->sregs.efer & VCPU_EFER_FLAG_LME, 0);

	kvm_vcpu_destroy(valid_vm, valid_vcpu);
}

void test_kvm_vcpu_set_regs() {
	struct kvm_vcpu invalid_vcpu;
	memset(&invalid_vcpu, 0, sizeof(struct kvm_vcpu));

	int err = kvm_vcpu_set_regs(&invalid_vcpu);
	CU_ASSERT_EQUAL(err, -EIO);

	struct kvm_vm *valid_vm = init_test_vm();
	err = kvm_vcpu_create(valid_vm, VM_MODE_X86_64);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	struct kvm_vcpu *valid_vcpu = valid_vm->vcpus->vcpu;
	CU_ASSERT_FATAL(valid_vcpu->fd > 0);

	valid_vcpu->regs.rip = 0x1234;
	valid_vcpu->regs.rcx = 0x5678;
	valid_vcpu->sregs.cr2 = 0x9101;
	err = kvm_vcpu_set_regs(valid_vcpu);
	CU_ASSERT_EQUAL(err, 0);

	err = kvm_vcpu_get_regs(valid_vcpu);
	CU_ASSERT_EQUAL(err, 0);

	CU_ASSERT_EQUAL(valid_vcpu->regs.rip, 0x1234);
	CU_ASSERT_EQUAL(valid_vcpu->regs.rcx, 0x5678);
	CU_ASSERT_EQUAL(valid_vcpu->sregs.cr2, 0x9101);

	err = kvm_vcpu_destroy(valid_vm, valid_vcpu);
	CU_ASSERT_EQUAL(err, 0);
}

void test_kvm_vcpu_destroy() {

	/* delete an invalid element */
	struct kvm_vcpu invalid_vcpu;
	memset(&invalid_vcpu, 0, sizeof(struct kvm_vcpu));

	struct kvm_vm *valid_vm = init_test_vm();
	int err = kvm_vcpu_destroy(valid_vm, &invalid_vcpu);
	CU_ASSERT_EQUAL(err, -1);

	/* delete the only element */
	struct kvm_vcpu *vcpu = malloc(sizeof(struct kvm_vcpu));
	err = kvm_vcpu_add_tail(valid_vm, vcpu);
	CU_ASSERT_EQUAL(err, 0);

	err = kvm_vcpu_destroy(valid_vm, vcpu);
	CU_ASSERT_EQUAL(err, 0);

	/* delete the middle element */
	vcpu = malloc(sizeof(struct kvm_vcpu));
	err = kvm_vcpu_add_tail(valid_vm, vcpu);
	CU_ASSERT_EQUAL(err, 0);
	struct kvm_vcpu *vcpu_1 = malloc(sizeof(struct kvm_vcpu));
	err = kvm_vcpu_add_tail(valid_vm, vcpu_1);
	CU_ASSERT_EQUAL(err, 0);
	struct kvm_vcpu *vcpu_2 = malloc(sizeof(struct kvm_vcpu));
	err = kvm_vcpu_add_tail(valid_vm, vcpu_2);
	CU_ASSERT_EQUAL(err, 0);
	err = kvm_vcpu_destroy(valid_vm, vcpu_1);
	CU_ASSERT_EQUAL(err, 0);
	CU_ASSERT_PTR_EQUAL(vcpu, valid_vm->vcpus->vcpu);
	CU_ASSERT_PTR_EQUAL(vcpu_2, valid_vm->vcpus->next->vcpu);

	/* delete the first element of two */
	err = kvm_vcpu_destroy(valid_vm, vcpu);
	CU_ASSERT_EQUAL(err, 0);
	CU_ASSERT_PTR_EQUAL(vcpu_2, valid_vm->vcpus->vcpu);

	/* delete the last element */
	err = kvm_vcpu_destroy(valid_vm, vcpu_2);
	CU_ASSERT_EQUAL(err, 0);
	CU_ASSERT_PTR_NULL(valid_vm->vcpus);
}

void test_kvm_vcpu_add_tail() {
	struct kvm_vm the_vm;
	memset(&the_vm, 0, sizeof(struct kvm_vm));

	struct kvm_vcpu vcpu_0;
	int err = kvm_vcpu_add_tail(&the_vm, &vcpu_0);
	CU_ASSERT_EQUAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(the_vm.vcpus);
	CU_ASSERT_PTR_EQUAL(the_vm.vcpus->vcpu, &vcpu_0);

	struct kvm_vcpu vcpu_1;
	err = kvm_vcpu_add_tail(&the_vm, &vcpu_1);
	CU_ASSERT_EQUAL(err, 0);
	CU_ASSERT_PTR_EQUAL(the_vm.vcpus->vcpu, &vcpu_0);
	CU_ASSERT_PTR_EQUAL(the_vm.vcpus->next->vcpu, &vcpu_1);

	struct kvm_vcpu vcpu_2;
	err = kvm_vcpu_add_tail(&the_vm, &vcpu_2);
	CU_ASSERT_EQUAL(err, 0);
	CU_ASSERT_PTR_EQUAL(the_vm.vcpus->vcpu, &vcpu_0);
	CU_ASSERT_PTR_EQUAL(the_vm.vcpus->next->vcpu, &vcpu_1);
	CU_ASSERT_PTR_EQUAL(the_vm.vcpus->next->next->vcpu, &vcpu_2);
}
