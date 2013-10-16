#pragma once

#include <vcpu.h>

struct elkvm_sw_bp {
  uint64_t guest_virtual_addr;
  uint8_t orig_inst;
  unsigned count;
};

int elkvm_handle_debug(struct kvm_vm *, struct kvm_vcpu *);
int elkvm_set_guest_debug(struct kvm_vcpu *vcpu);

struct elkvm_sw_bp *elkvm_find_bp_for_rip(struct kvm_vcpu *, uint64_t rip);
