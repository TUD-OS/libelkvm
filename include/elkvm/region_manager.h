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

#include <array>
#include <memory>
#include <vector>

#include <elkvm/pager.h>
#include <elkvm/region.h>

namespace Elkvm {
  class RegionManager {
    public:
      static const unsigned n_freelists = 17; // TODO make configurable constant
    private:
      std::vector<std::shared_ptr<Region>> allocated_regions;
      std::array<std::vector<std::shared_ptr<Region>>, n_freelists> freelists;

      PagerX86_64 pager;

      int add_chunk(size_t size, const std::string &purpose);

    public:
      RegionManager(int vmfd);

      bool address_valid(const void *host_p) const;
      bool host_address_mapped(const void * const) const;
      bool same_region(const void *p1, const void *p2) const;

      void add_free_region(std::shared_ptr<Region> region);
      std::shared_ptr<Region> allocate_region(size_t size,
          const std::string &purpose="anon region");
      void free_region(std::shared_ptr<Region> r);
      void free_region(void *host_p, size_t sz);
      void use_region(std::shared_ptr<Region> r);

      std::shared_ptr<Region> find_free_region(size_t size);
      std::shared_ptr<Region> find_region(const void *host_p) const;
      std::shared_ptr<Region> find_region(guestptr_t addr) const;

      void dump_regions() const;
      void dump_mappings() const;

      /* XXX make this const */
      PagerX86_64 &get_pager() { return pager; }
      const PagerX86_64 &get_pager() const { return pager; }
  };

  std::array<std::vector<Region>, RegionManager::n_freelists>::size_type
    get_freelist_idx(const size_t size);

  //namespace Elkvm
}
