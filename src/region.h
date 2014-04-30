#pragma once

#include <array>
#include <vector>

#include <elkvm.h>

namespace Elkvm {

  class Region {
    private:
      void *host_p;
      guestptr_t addr;
      size_t size;
      bool free;
    public:
      Region(void *chunk_p, size_t sz) :
        host_p(chunk_p),
        addr(0),
        size(sz),
        free(true) {}
      bool contains_address(void *addr);
      void set_free() { free = true; }
      void set_used() { free = false; }
      struct elkvm_memory_region *c_region();
  };

  class RegionManager {
    private:
      std::array<std::vector<Region>, 15> freelists;
      void split_free_region(Region &region);
      int add_chunk(struct kvm_pager *pager, uint64_t size);

    public:
      Region &allocate_region(size_t size);
      Region &find_region(void *host_p);
      Region &find_region(guestptr_t addr);

  };

  static RegionManager rm;

//namespace Elkvm
}

