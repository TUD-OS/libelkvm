#pragma once

#include <iostream>
#include <memory>

#include <elkvm.h>

#include <sys/mman.h>

namespace Elkvm {
  class Region;

  class Mapping {
    private:
      struct kvm_pager * pager;
      void *host_p;
      guestptr_t addr;
      size_t length;
      unsigned mapped_pages;
      int prot;
      int flags;
      int fd;
      off_t offset;
      std::shared_ptr<Region> region;

    public:
      Mapping(guestptr_t guest_addr, size_t l, int pr, int f, int fdes, off_t off,
          struct kvm_pager * pa);
      Mapping(std::shared_ptr<Region> r, guestptr_t guest_addr, size_t l, int pr, int f,
          int fdes, off_t off, struct kvm_pager * pa);
      bool contains_address(void *p);
      struct region_mapping *c_mapping();
      Mapping slice_center(off_t off, size_t len, int new_fd, off_t new_offset);
      size_t get_length() const { return length; }
      int get_fd() const { return fd; }
      off_t get_offset() const { return offset; }
      unsigned get_pages() const { return mapped_pages; }
      void set_host_p(void *p) { host_p = p; }
      void *base_address() const { return host_p; }
      guestptr_t guest_address() const { return addr; }
      bool anonymous() const { return flags & MAP_ANONYMOUS; }
      bool writeable() const { return flags & PROT_WRITE; }
      bool executable() const { return flags & PROT_EXEC; }
      void unmap_pages(unsigned pages) { mapped_pages -= pages; }
      bool all_unmapped() { return mapped_pages == 0; }
      int fill();
      void sync_back(struct region_mapping *mapping);
      int map_self();
  };

  std::ostream &print(std::ostream &, const Mapping &);
  bool operator==(const Mapping &, const Mapping &);

}
