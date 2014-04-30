#pragma once

#include <array>
#include <vector>

#include <elkvm.h>

namespace Elkvm {

  class Region {
    private:
      void *host_p;
      guestptr_t addr;
      size_t rsize;
      bool free;
    public:
      Region(void *chunk_p, size_t size) :
        host_p(chunk_p),
        addr(0),
        rsize(size),
        free(true) {}
      void *base_address() const { return host_p; }
      struct elkvm_memory_region *c_region() const;
      bool contains_address(const void *addr) const;
      void *last_valid_address() const;
      size_t size() const { return rsize; }
      void set_free() { free = true; addr = 0x0; }
      void set_used() { free = false; }
      Region slice_begin(const size_t size);
  };

  bool same_region(const void *p1, const void *p2);

  class RegionManager {
    private:
      std::array<std::vector<Region>, 15> freelists;
      void split_free_region(Region &region);
      int add_chunk(struct kvm_pager *pager, uint64_t size);

    public:
      bool address_valid(const void *host_p) const;
      Region &allocate_region(size_t size);
      Region &find_region(const void *host_p) const;
      Region &find_region(const guestptr_t addr) const;
      void free_region(Region &r);
      void free_region(const void *host_p, const size_t sz);

  };

  std::array<std::vector<Region>, 15>::size_type get_freelist_idx(const size_t size);

  static RegionManager rm;

//namespace Elkvm
}

