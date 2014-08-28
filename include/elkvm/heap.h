#pragma once

#include <stdbool.h>

#include <iostream>
#include <memory>
#include <vector>

#include <elkvm.h>
#include <region.h>
#include <region_manager.h>
#include <mapping.h>

namespace Elkvm {
  class HeapManager {
    private:
      std::vector<Mapping> mappings_for_brk;
      std::vector<Mapping> mappings_for_mmap;
      std::shared_ptr<RegionManager> _rm;
      guestptr_t curbrk;

      int grow(size_t sz);
      int shrink(guestptr_t newbrk);
      Mapping &create_mapping(guestptr_t addr, size_t length, int prot, int flags,
          int fd, off_t off);

    public:
      HeapManager(std::shared_ptr<RegionManager> rm) :
        _rm(rm),
        curbrk(0x0)
    {}
      int init(std::shared_ptr<Region> data, size_t sz);
      int brk(guestptr_t newbrk);
      guestptr_t get_brk() const { return curbrk; };
      bool contains_address(guestptr_t addr) const;
      bool brk_contains_address(guestptr_t addr) const
      { return (mappings_for_brk.front().guest_address() <= addr)
        && (addr < curbrk); }

      Mapping &find_mapping(guestptr_t addr);
      Mapping &find_mapping(void *host_p);
      bool address_mapped(guestptr_t addr) const;

      Mapping &get_mapping(guestptr_t addr, size_t length, int prot, int flags,
          int fd, off_t off);

      void add_mapping(const Mapping &mapping);
      void free_mapping(Mapping &mapping);

      void dump_mappings() const;

      int map(Mapping &m);
      int unmap(Mapping &m);
      int unmap(Mapping &m, guestptr_t unmap_addr, unsigned pages);

      void slice(Mapping &m, guestptr_t slice_base, size_t len);
      void slice_begin(Mapping &m, size_t len);
      void slice_center(Mapping &m, off_t off, size_t len);
      void slice_end(Mapping &m, guestptr_t slice_base);
  };

  //namespace Elkvm
}
