#pragma once

#include <iostream>
#include <memory>

#include <sys/mman.h>

#include <elkvm/types.h>

namespace Elkvm {
  class Region;

  class Mapping {
    private:
      void *host_p;
      guestptr_t addr;
      size_t length;
      unsigned mapped_pages;
      int prot;
      int flags;
      int fd;
      off_t offset;
      std::shared_ptr<Region> region;

      void slice_begin(size_t len);
      void slice_center(off_t off, size_t len);
      void slice_end(guestptr_t slice_base);

    public:
      Mapping(std::shared_ptr<Region> r, guestptr_t guest_addr,
          size_t l, int pr, int f, int fdes, off_t off);

      bool anonymous() const { return flags & MAP_ANONYMOUS; }
      bool contains_address(void *p) const;
      bool contains_address(guestptr_t a) const;
      bool fits_address(guestptr_t a) const;

      size_t grow(size_t sz);
      guestptr_t grow_to_fill();

      bool readable() const { return prot & PROT_READ; }
      bool executable() const { return prot & PROT_EXEC; }
      bool writeable() const { return prot & PROT_WRITE; }

      void *base_address() const { return host_p; }
      guestptr_t guest_address() const { return addr; }
      std::shared_ptr<Region> move_guest_address(off64_t off);
      int get_fd() const { return fd; }
      size_t get_length() const { return length; }
      void set_length(size_t len);
      off_t get_offset() const { return offset; }
      unsigned get_pages() const { return mapped_pages; }
      int get_prot() const { return prot; }
      int get_flags() const { return flags; }
      std::shared_ptr<Region> get_region() { return region; }

      bool all_unmapped() const { return mapped_pages == 0; }
      void set_unmapped() { length = mapped_pages = 0; }
      void pages_unmapped(unsigned pages) { mapped_pages -= pages; }

      struct region_mapping *c_mapping();
      void sync_back(struct region_mapping *mapping);
      int diff(struct region_mapping *mapping) const;

      int fill();

      void modify(int pr, int fl, int filedes, off_t o);
      void mprotect(int pr);
  };

  std::ostream &print(std::ostream &, const Mapping &);
  bool operator==(const Mapping &, const Mapping &);

}
