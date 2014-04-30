#pragma once

#include <array>

#include "list.h"

namespace Elkvm {

  class Region {
    private:
      void *host_p;
      guestptr_t addr;
      size_t size;
      bool free;
      bool down;
    public:
      bool contains_address(void *addr);
  };

  class RegionManager {
    private:
      std::array<Region, 15> freelists;
      void split_free_region(Region &region);

    public:
      Region allocate_region(size_t size);
      Region &find_region(void *host_p);
      Region &find_region(guestptr_t addr);

  };

//namespace Elkvm
}

