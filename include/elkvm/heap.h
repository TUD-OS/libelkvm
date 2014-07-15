#pragma once

#include <stdbool.h>

#include <iostream>
#include <memory>

#include "elkvm.h"
#include "region.h"

namespace Elkvm {
  class HeapManager {
    private:
      std::vector<Mapping> mappings;
      RegionManager &_rm;
      guestptr_t curbrk;

      int grow(size_t sz);
      int shrink(guestptr_t newbrk);

    public:
      HeapManager(RegionManager &rm) : _rm(rm) {}
      int init(std::shared_ptr<Region> data, size_t sz);
      int brk(guestptr_t newbrk);
      guestptr_t get_brk() const { return curbrk; };
      bool contains_address(guestptr_t addr) const
      { return (mappings.front().guest_address() <= addr) && (addr < curbrk); }
      Mapping &find_mapping(guestptr_t addr);
  };

  //namespace Elkvm
}
