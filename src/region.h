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
      guestptr_t guest_address() const { return addr; }
      void *last_valid_address() const;
      void set_free() { free = true; addr = 0x0; }
      void set_guest_addr(guestptr_t a) { addr = a; };
      void set_used() { free = false; }
      size_t size() const { return rsize; }
      Region slice_begin(const size_t size);
  };

  std::ostream &print(std::ostream &, const Region &);
  bool same_region(const void *p1, const void *p2);
  bool operator==(const Region, const void * const);

  class RegionManager {
    private:
      struct kvm_pager * pager;
      std::array<std::vector<Region>, 16> freelists;
      int add_chunk(const size_t size);
      int split_free_region(const size_t size);
      std::vector<Region> allocated_regions;

    public:
      void add_free_region(const Region &region);
      void add_system_chunk();
      bool address_valid(const void *host_p) const;
      Region &allocate_region(size_t size);
      Region &find_region(const void *host_p);
      Region &find_region(const guestptr_t addr);
      void free_region(Region &r);
      void free_region(void *host_p, const size_t sz);
      bool host_address_mapped(const void * const) const;
      void set_pager(struct kvm_pager *const p) { pager = p; }
  };

  std::array<std::vector<Region>, 16>::size_type get_freelist_idx(const size_t size);

  static RegionManager rm;

//namespace Elkvm
}

