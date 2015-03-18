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

#include <memory>

#include <elkvm/mapping.h>

namespace Elkvm {

  class Region {
    private:
      void *host_p;
      guestptr_t addr;
      size_t rsize;
      bool free;
      std::string name;

    public:
      Region(void *chunk_p, size_t size, const std::string &title="anon region",
          bool f = true) :
        host_p(chunk_p),
        addr(0),
        rsize(size),
        free(f),
        name(title)
    {}

	  Region(const Region&) = delete;
	  Region& operator=(const Region&) = delete;

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
      std::shared_ptr<Region> slice_begin(const size_t size,
          const std::string &purpose="anon region");
      std::pair<std::shared_ptr<Region>, std::shared_ptr<Region>>
        slice_center(off_t off, size_t len);
      std::string const& getName() const { return this->name; }
  };

  std::ostream &print(std::ostream &, const Region &);
  bool operator==(const Region &, const Region &);

//namespace Elkvm
}

