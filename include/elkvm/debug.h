#pragma once

#include <elkvm/elkvm.h>

int elkvm_handle_debug(Elkvm::VM *);

namespace Elkvm {
  std::ostream &print_memory(std::ostream &os, const VM &vm, guestptr_t addr,
      size_t sz);

//namespace Elkvm
}
