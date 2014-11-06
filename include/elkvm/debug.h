#pragma once

#include <elkvm/elkvm.h>
#include <elkvm/elkvm-internal.h>
#include <elkvm/vcpu.h>

int elkvm_handle_debug(Elkvm::VM *);
int elkvm_set_guest_debug(std::shared_ptr<VCPU> vcpu);

/**
 * \brief Set the VCPU in singlestepping mode
 */
int elkvm_debug_singlestep(std::shared_ptr<VCPU> vcpu);

/**
 * \brief Get the VCPU out of singlestepping mode
 */
int elkvm_debug_singlestep_off(std::shared_ptr<VCPU> vcpu);
