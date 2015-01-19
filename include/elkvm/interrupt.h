#pragma once

#include <memory>

#include <elkvm/elkvm.h>
#include <elkvm/vcpu.h>

namespace Elkvm {

namespace Interrupt {
  const int success = 0;
  const int failure = 1;
  namespace Vector {
    const int debug_trap               = 0x01;
    const int stack_segment_fault      = 0x0c;
    const int general_protection_fault = 0x0d;
    const int page_fault               = 0x0e;
  }

  int handle_stack_segment_fault(uint64_t code);
  int handle_general_protection_fault(uint64_t code);
  int handle_page_fault(VM &vm, const std::shared_ptr<VCPU>& vcpu,
      uint64_t code);
  int handle_debug_trap(const std::shared_ptr<VCPU>& vcpu, uint64_t code);

  int handle_segfault(guestptr_t pfla);
}

//namespace Elkvm
}

