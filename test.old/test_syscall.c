#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <check.h>
#include <elkvm.h>
#include <pager.h>
#include <syscall.h>
#include <vcpu.h>

struct kvm_vm syscall_vm;

void syscall_setup() {
	syscall_vm.fd = 0x42;
	syscall_vm.vcpus = malloc(sizeof(struct vcpu_list));
	syscall_vm.vcpus->vcpu = malloc(sizeof(struct kvm_vcpu));
	syscall_vm.vcpus->next = NULL;

  int err = elkvm_region_setup(&syscall_vm);
  assert(err == 0);

	err = kvm_pager_initialize(&syscall_vm, PAGER_MODE_X86_64);
	//int err = posix_memalign((void **)&syscall_vm.pager.system_chunk.userspace_addr,
	//		0x1000, 0x1000);
	//assert(err == 0);

	//syscall_vm.pager.system_chunk.guest_phys_addr = 0x0;
	//syscall_vm.pager.system_chunk.memory_size = 0x1000;
}

void syscall_teardown() {
	free(syscall_vm.vcpus->vcpu);
	free(syscall_vm.vcpus);
	free((void *)syscall_vm.pager.system_chunk.userspace_addr);
}

START_TEST(test_handle_syscall) {
	struct kvm_vcpu *vcpu = syscall_vm.vcpus->vcpu;

	vcpu->regs.rax = 0x3f;
	vcpu->regs.rip = 0x0;
	vcpu->regs.rcx = 0x500;
  vcpu->sregs.cr3 = 0x0;


	uint32_t opcode = 0x0F01C4;
	memcpy((void *)syscall_vm.pager.system_chunk.userspace_addr, &opcode, 3);
	opcode = 0x0F05;
	memcpy((void *)syscall_vm.pager.system_chunk.userspace_addr, &opcode, 2);

//	int cont = elkvm_handle_vm_shutdown(&syscall_vm, vcpu);
//	ck_assert_int_eq(cont, 1);
}
END_TEST

START_TEST(test_handle_tf) {
	ck_abort_msg("TF handler Test not implemented");
}
END_TEST

Suite *syscall_suite() {
	Suite *s = suite_create("Syscall");

	TCase *tc_handle_vm_shutdown = tcase_create("elkvm_handle_vcpu_shutdown");
	tcase_add_checked_fixture(tc_handle_vm_shutdown, syscall_setup, syscall_teardown);
	tcase_add_test(tc_handle_vm_shutdown, test_handle_tf);
	tcase_add_test(tc_handle_vm_shutdown, test_handle_syscall);
	suite_add_tcase(s, tc_handle_vm_shutdown);

	return s;
}
