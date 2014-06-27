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

      bool anonymous() const { return flags & MAP_ANONYMOUS; }
      bool contains_address(void *p) const;
      bool contains_address(guestptr_t a) const;
      bool readable() const { return prot & PROT_READ; }
      bool executable() const { return prot & PROT_EXEC; }
      bool writeable() const { return prot & PROT_WRITE; }

      void *base_address() const { return host_p; }
      guestptr_t guest_address() const { return addr; }
      int get_fd() const { return fd; }
      size_t get_length() const { return length; }
      off_t get_offset() const { return offset; }
      unsigned get_pages() const { return mapped_pages; }
      int get_prot() const { return prot; }
      int get_flags() const { return flags; }

      bool all_unmapped() { return mapped_pages == 0; }

      struct region_mapping *c_mapping();
      void sync_back(struct region_mapping *mapping);

      void slice(guestptr_t slice_base, size_t len);
      void slice_begin(size_t len);
      void slice_center(off_t off, size_t len);
      void slice_end(guestptr_t slice_base, size_t len);

      int fill();

      int map_self();
      void modify(int pr, int fl, int filedes, off_t o);
      int mprotect(int pr);
      int unmap(guestptr_t unmap_addr, unsigned pages);
  };

  std::ostream &print(std::ostream &, const Mapping &);
  bool operator==(const Mapping &, const Mapping &);

}
