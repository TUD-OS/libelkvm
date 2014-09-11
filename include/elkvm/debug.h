#pragma once

#include <elkvm/elkvm.h>
#include <elkvm/elkvm-internal.h>
#include <elkvm/vcpu.h>

int elkvm_handle_debug(Elkvm::VM *);
int elkvm_set_guest_debug(struct kvm_vcpu *vcpu);

/**
 * \brief Set the VCPU in singlestepping mode
 */
int elkvm_debug_singlestep(struct kvm_vcpu *vcpu);

/**
 * \brief Get the VCPU out of singlestepping mode
 */
int elkvm_debug_singlestep_off(struct kvm_vcpu *vcpu);
