#pragma once

#include <memory>

#include <elkvm/elkvm.h>
#include <elkvm/vcpu.h>

namespace Elkvm {

namespace Interrupt {
  const int success = 0;
  const int failure = 1;
  namespace Vector {
    const int stack_segment_fault      = 0x0c;
    const int general_protection_fault = 0x0d;
    const int page_fault               = 0x0e;
  }

  int handle_stack_segment_fault(uint64_t code);
  int handle_general_protection_fault(uint64_t code);
  int handle_page_fault(VM &vm, std::shared_ptr<struct kvm_vcpu> vcpu,
      uint64_t code);

  int handle_segfault(guestptr_t pfla);
}

//namespace Elkvm
}

