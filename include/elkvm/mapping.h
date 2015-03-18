/* * libelkvm - A library that allows execution of an ELF binary inside a virtual
 * machine without a full-scale operating system
 * Copyright (C) 2013-2015 Florian Pester <fpester@os.inf.tu-dresden.de>, Björn
 * Döbel <doebel@os.inf.tu-dresden.de>,   economic rights: Technische Universitaet
 * Dresden (Germany)
 *
 * This file is part of libelkvm.
 *
 * libelkvm is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * libelkvm is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libelkvm.  If not, see <http://www.gnu.org/licenses/>.
 */

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

      Mapping(const Mapping& orig)
        : host_p(orig.base_address()),
          addr(orig.guest_address()),
          length(orig.get_length()),
          mapped_pages(orig.get_pages()),
          prot(orig.get_prot()),
          flags(orig.get_flags()),
          fd(orig.get_fd()),
          offset(orig.get_offset()),
          region(orig.get_region())
      { }

      Mapping& operator=(const Mapping& other)
      {
        host_p = other.base_address();
        addr   = other.guest_address();
        length = other.get_length();
        mapped_pages = other.get_pages();
        prot         = other.get_prot();
        flags        = other.get_flags();
        fd           = other.get_fd();
        offset       = other.get_offset();
        region       = other.get_region();
        return *this;
      }

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
      std::shared_ptr<Region> get_region() const { return region; }

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
