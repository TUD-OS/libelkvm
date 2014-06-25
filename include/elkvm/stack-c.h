#pragma once

#include "vcpu.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Push a value onto the Stack of the VM
 */
int elkvm_pushq(struct kvm_vm *, struct kvm_vcpu *, uint64_t);

/*
 * Pop a value from the VM's Stack
 */
uint64_t elkvm_popq(struct kvm_vm *, struct kvm_vcpu *);

/*
 * Dump the stack to stdout
 */
void elkvm_dump_stack(struct kvm_vm *, struct kvm_vcpu *vcpu);

bool elkvm_is_stack_expansion(struct kvm_vm *vm, guestptr_t pfla);
bool elkvm_check_stack_grow(guestptr_t pfla);

int elkvm_initialize_stack(struct kvm_vm *vm);

guestptr_t elkvm_get_kernel_stack_base();


#ifdef __cplusplus
}
#endif

