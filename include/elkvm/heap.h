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

#include <stdbool.h>

#include <iostream>
#include <memory>
#include <vector>

#include <elkvm/region.h>
#include <elkvm/region_manager.h>
#include <elkvm/mapping.h>

namespace Elkvm {
  class HeapManager {
    private:
      std::vector<Mapping> mappings_for_brk;
      std::vector<Mapping> mappings_for_mmap;
      std::shared_ptr<RegionManager> _rm;
      guestptr_t curbrk;

      int grow(size_t sz);
      int shrink(guestptr_t newbrk);
      void unmap_to_new_size(Mapping &m, size_t new_size);
      guestptr_t create_resized_mapping(Mapping &m, size_t new_size);

      void slice_region(Mapping &m, off_t off, size_t len);

      void free_unused_mappings(guestptr_t brk);

    public:
      HeapManager(std::shared_ptr<RegionManager> rm) :
		mappings_for_brk(),
		mappings_for_mmap(),
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

      Mapping &create_mapping(guestptr_t addr, size_t length, int prot, int flags,
          int fd, off_t off, std::shared_ptr<Region> r = nullptr);
      Mapping &get_mapping(guestptr_t addr, size_t length, int prot, int flags,
          int fd, off_t off);

      void free_mapping(Mapping &mapping);

      void dump_mappings() const;

      int map(Mapping &m);
      guestptr_t remap(Mapping &m, guestptr_t new_address_p, size_t new_size, int flags);
      int unmap(Mapping &m);
      int unmap(Mapping &m, guestptr_t unmap_addr, unsigned pages);

      void slice(Mapping &m, guestptr_t slice_base, size_t len);
      void slice_begin(Mapping &m, size_t len);
      void slice_center(Mapping &m, off_t off, size_t len);
      void slice_end(Mapping &m, guestptr_t slice_base);
  };

  //namespace Elkvm
}
