#pragma once

#include <vcpu.h>

/*
 * \brief check if the shutdown reason is a call from the guest
 * manager to the host
 * returns 1 if the vm is to keep running
 * returns 0 if the vm has had an error (#TF) and should stop running
 */
int elkvm_handle_vm_shutdown(struct kvm_vm *, struct kvm_vcpu *);

/*
 * \brief check what kind of syscall has been made by the guest
 * and call the appropriate handler func in the userspace binary
 */
int elkvm_handle_syscall(struct kvm_vm *);
