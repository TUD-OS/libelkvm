#include <elkvm/elkvm-log.h>
#include <elkvm/interrupt.h>

int Elkvm::VM::handle_interrupt(struct kvm_vcpu *vcpu) {
  uint64_t interrupt_vector = vcpu->pop();

  if(debug_mode()) {
    DBG() << " INTERRUPT with vector " << std::hex << "0x" << interrupt_vector
      << " detected";
    kvm_vcpu_get_sregs(vcpu);
    kvm_vcpu_dump_regs(vcpu);
    dump_stack(vcpu);
  }

  /* Stack Segment */
  if(interrupt_vector == 0x0c) {
    uint64_t err_code = vcpu->pop();
    ERROR() << "STACK SEGMENT FAULT\n";
    ERROR() << "Error Code: " << err_code << "\n";
    return 1;
  }

  /* General Protection */
  if(interrupt_vector == 0x0d) {
    uint64_t err_code = vcpu->pop();
    ERROR() << "GENERAL PROTECTION FAULT\n";
    ERROR() << "Error Code:" << err_code << "\n";
    return 1;

  }

  /* page fault */
  if(interrupt_vector == 0x0e) {
    int err = kvm_vcpu_get_sregs(vcpu);
    if(err) {
      return err;
    }

    if(vcpu->sregs.cr2 == 0x0) {
      ERROR() << "\n\nABORT: SEGMENTATION FAULT\n\n";
      exit(1);
      return 1;
    }

    uint32_t err_code = vcpu->pop();
    void *hp = get_region_manager()->get_pager().get_host_p(vcpu->sregs.cr2);
    Elkvm::dump_page_fault_info(vcpu->sregs.cr2, err_code, hp);
    if(hp) {
      get_region_manager()->get_pager().dump_page_tables();
    }
    if(vcpu->check_pagefault(err_code, debug_mode())) {
      vcpu->stack.expand();
      return 0;
    }

    return 1;
  }

  return 1;
}


