#pragma once

#include <vcpu.h>

struct elkvm_sw_bp {
  uint64_t guest_virtual_addr;
  uint8_t orig_inst;
  unsigned count;
};

int elkvm_set_guest_debug(struct kvm_vcpu *vcpu);
