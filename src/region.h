#pragma once

#include <array>
#include <memory>
#include <vector>

#include <elkvm.h>
#include <mapping.h>

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
      bool contains_address(guestptr_t addr) const;
      off64_t offset_in_region(guestptr_t addr) const;
      size_t space_after_address(const void * const) const;
      guestptr_t guest_address() const { return addr; }
      bool is_free() const { return free; }
      void *last_valid_address() const;
      guestptr_t last_valid_guest_address() const;
      void set_free() { free = true; addr = 0x0; }
      void set_guest_addr(guestptr_t a) { addr = a; };
      void set_used() { free = false; }
      size_t size() const { return rsize; }
      std::shared_ptr<Region> slice_begin(const size_t size);
      void slice_center(off_t off, size_t len);
  };

  std::ostream &print(std::ostream &, const Region &);
  bool same_region(const void *p1, const void *p2);
  bool operator==(const Region &, const Region &);

  class RegionManager {
    private:
      struct kvm_pager * pager;
      std::array<std::vector<std::shared_ptr<Region>>, 16> freelists;
      int add_chunk(size_t size);
      std::vector<std::shared_ptr<Region>> allocated_regions;
      std::vector<Mapping> mappings;

    public:
      void add_free_region(std::shared_ptr<Region> region);
      void add_system_chunk();
      bool address_valid(const void *host_p) const;
      std::shared_ptr<Region> allocate_region(size_t size);
      std::shared_ptr<Region> find_free_region(size_t size);
      std::shared_ptr<Region> find_region(const void *host_p);
      std::shared_ptr<Region> find_region(guestptr_t addr);
      void free_region(std::shared_ptr<Region> r);
      void free_region(void *host_p, size_t sz);
      bool host_address_mapped(const void * const) const;
      void set_pager(struct kvm_pager *const p) { pager = p; }
      void use_region(std::shared_ptr<Region> r);
      Mapping &find_mapping(void *host_p);
      Mapping &find_mapping(guestptr_t addr);
      void add_mapping(Mapping &mapping);
      void free_mapping(Mapping &mapping);
  };

  std::array<std::vector<Region>, 16>::size_type get_freelist_idx(const size_t size);
//namespace Elkvm
}

