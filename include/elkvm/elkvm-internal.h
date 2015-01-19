#pragma once

#if 1
#include <vector>

#include <elkvm/heap.h>
#include <elkvm/region.h>
#include <elkvm/region_manager.h>
#include <elkvm/stack.h>

namespace Elkvm {

  bool operator==(const VM &lhs, const VM &rhs);
  unsigned get_hypercall_type(const std::shared_ptr<VCPU>&);

  //namespace Elkvm
}
#endif
