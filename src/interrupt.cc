#include <memory>

#include <elkvm/elkvm-log.h>
#include <elkvm/interrupt.h>
#include <elkvm/vcpu.h>

int Elkvm::VM::handle_interrupt(std::shared_ptr<struct kvm_vcpu> vcpu) {
  uint64_t interrupt_vector = vcpu->pop();

  if(debug_mode()) {
    DBG() << " INTERRUPT with vector " << std::hex << "0x" << interrupt_vector
      << " detected";
    kvm_vcpu_get_sregs(vcpu.get());
    kvm_vcpu_dump_regs(vcpu.get());
    dump_stack(vcpu.get());
  }

  uint64_t err_code = vcpu->pop();
  if(interrupt_vector == Interrupt::Vector::stack_segment_fault) {
    return Elkvm::Interrupt::handle_stack_segment_fault(err_code);
  }

  if(interrupt_vector == Interrupt::Vector::general_protection_fault) {
    return Elkvm::Interrupt::handle_general_protection_fault(err_code);
  }

  if(interrupt_vector == Interrupt::Vector::page_fault) {
    return Elkvm::Interrupt::handle_page_fault(*this, vcpu, err_code);
  }

  return 1;
}

int Elkvm::Interrupt::handle_stack_segment_fault(uint64_t code) {
  ERROR() << "STACK SEGMENT FAULT\n";
  ERROR() << "Error Code: " << code << "\n";
  return 1;
}

int Elkvm::Interrupt::handle_general_protection_fault(uint64_t code) {
  ERROR() << "GENERAL PROTECTION FAULT\n";
  ERROR() << "Error Code:" << code << "\n";
  return 1;
}

int Elkvm::Interrupt::handle_page_fault(VM &vm,
    std::shared_ptr<struct kvm_vcpu> vcpu,
    uint64_t code) {
  int err = kvm_vcpu_get_sregs(vcpu.get());
  if(err) {
    return err;
  }

  if(vcpu->sregs.cr2 <= 0x1000) {
    ERROR() << "\n\nABORT: SEGMENTATION FAULT\n\n";
    exit(EXIT_FAILURE);
    return 1;
  }

  void *hp = vm.get_region_manager()->get_pager().get_host_p(vcpu->sregs.cr2);
  Elkvm::dump_page_fault_info(vcpu->sregs.cr2, code, hp);
  if(hp) {
    vm.get_region_manager()->get_pager().dump_page_tables();
  }
  if(vcpu->check_pagefault(code, vm.debug_mode())) {
    return 0;
  }

  return 1;
}
