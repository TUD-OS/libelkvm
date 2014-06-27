#pragma once

#include <stdbool.h>
#include <memory>

#include "elkvm.h"
#include "region.h"

namespace Elkvm {
  class HeapManager {
    private:
      struct kvm_pager * pager;
      std::vector<Mapping> mappings;
      guestptr_t curbrk;

      int grow(size_t sz);
      int shrink(guestptr_t newbrk);

    public:
      int init(std::shared_ptr<Region> data, size_t sz);
      int brk(guestptr_t newbrk);
      guestptr_t get_brk() const { return curbrk; };
      void set_pager(struct kvm_pager *const p) { pager = p; }
  };

  //namespace Elkvm
}
