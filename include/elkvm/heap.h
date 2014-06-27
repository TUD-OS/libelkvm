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
      int grow_in_region(guestptr_t newbrk);
      int shrink(guestptr_t newbrk);
      int map_heap(guestptr_t newbrk, off64_t off);

    public:
      int init(std::shared_ptr<Region> data, size_t sz);
      int brk(guestptr_t newbrk);
      guestptr_t get_brk() const { return curbrk; };
      bool address_in_heap_region(guestptr_t guest_addr) const {
        return guest_addr <= heap_regions.back()->last_valid_guest_address();
      }
      guestptr_t last_heap_address() const {
        return heap_regions.back()->last_valid_guest_address();
      }
      void set_pager(struct kvm_pager *const p) { pager = p; }
  };

  //namespace Elkvm
}
