#pragma once

#include <elkvm.h>
#include <elkvm-internal.h>
#include <vcpu.h>

namespace Elkvm {
  void dump_memory(VMInternals vmi, guestptr_t addr);

  //namespace Elkvm
}

int elkvm_handle_debug(Elkvm::kvm_vm *);
int elkvm_set_guest_debug(struct kvm_vcpu *vcpu);

/**
 * \brief Set the VCPU in singlestepping mode
 */
int elkvm_debug_singlestep(struct kvm_vcpu *vcpu);

/**
 * \brief Get the VCPU out of singlestepping mode
 */
int elkvm_debug_singlestep_off(struct kvm_vcpu *vcpu);
