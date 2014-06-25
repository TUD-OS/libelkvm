#pragma once

#include <elkvm.h>
#include <vcpu.h>

#ifdef __cplusplus
extern "C" {
#endif

int elkvm_handle_debug(struct kvm_vm *);
int elkvm_set_guest_debug(struct kvm_vcpu *vcpu);

/**
 * \brief Set the VCPU in singlestepping mode
 */
int elkvm_debug_singlestep(struct kvm_vcpu *vcpu);

/**
 * \brief Get the VCPU out of singlestepping mode
 */
int elkvm_debug_singlestep_off(struct kvm_vcpu *vcpu);

void elkvm_dump_memory(struct kvm_vm *vm, uint64_t addr);

#ifdef __cplusplus
}
#endif
