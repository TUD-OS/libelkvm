#pragma once

#include <iostream>

#include <elkvm.h>

#include <sys/mman.h>

namespace Elkvm {

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
    public:
      Mapping(void *p, guestptr_t guest_addr, size_t l, int pr, int f, int fdes, off_t off)
        : host_p(p), addr(guest_addr), length(l), prot(pr), flags(f), fd(fdes), offset(off)
      { mapped_pages = pages_from_size(length); }
      bool contains_address(void *p)
        { return (host_p <= p) && (p < (reinterpret_cast<char *>(host_p) + length)); }
      struct region_mapping *c_mapping();
      void slice_center();
      size_t get_length() const { return length; }
      int get_fd() const { return fd; }
      off_t get_offset() const { return offset; }
      unsigned get_pages() const { return mapped_pages; }
      void set_host_p(void *p) { host_p = p; }
      void *base_address() const { return host_p; }
      guestptr_t guest_address() const { return addr; }
      void sync_guest_to_host_addr() { addr = reinterpret_cast<guestptr_t>(host_p); }
      bool anonymous() const { return flags & MAP_ANONYMOUS; }
      bool writeable() const { return flags & PROT_WRITE; }
      bool executable() const { return flags & PROT_EXEC; }
      void unmap_pages(unsigned pages) { mapped_pages -= pages; }
      bool all_unmapped() { return mapped_pages == 0; }
  };

  std::ostream &print(std::ostream &, const Mapping &);
  bool operator==(const Mapping &, const Mapping &);

}
