//
// libelkvm - A library that allows execution of an ELF binary inside a virtual
// machine without a full-scale operating system
// Copyright (C) 2013-2015 Florian Pester <fpester@os.inf.tu-dresden.de>, Björn
// Döbel <doebel@os.inf.tu-dresden.de>,   economic rights: Technische Universitaet
// Dresden (Germany)
//
// This file is part of libelkvm.
//
// libelkvm is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// libelkvm is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with libelkvm.  If not, see <http://www.gnu.org/licenses/>.
//

#include <algorithm>
#include <cstring>
#include <memory>
#include <iostream>

#include <elkvm/elkvm-log.h>
#include <elkvm/heap.h>
#include <elkvm/region.h>
#include <elkvm/region_manager.h>

namespace Elkvm {
  RegionManager::RegionManager(int vmfd)
	: allocated_regions(),
	  freelists(),
	  pager(vmfd)
  {
    auto sysregion = allocate_region(ELKVM_PAGER_MEMSIZE, "ELKVM Pager Memory");
    pager.set_pml4(sysregion);
  }

  void RegionManager::dump_regions() const {
    INFO() << "DUMPING ALL REGIONS:";
    INFO() << "====================";
    for(const auto &reg : allocated_regions) {
      print(std::cout, *reg);
    }

    std::cout << std::endl << std::endl;
  }

  std::shared_ptr<Region> RegionManager::allocate_region(size_t size,
      const std::string &purpose) {
    auto r = find_free_region(size);

    if(r == nullptr) {
      int err = add_chunk(size, purpose);
      assert(err == 0 && "could not allocate memory for new region");

      r = find_free_region(size);
      assert(r != nullptr && "should have free region after allocation");
    }

    if(r->size() > pagesize_align(size)) {
      auto new_region = r->slice_begin(size, purpose);
      add_free_region(r);
      r = new_region;
    }

    use_region(r);

    assert(size <= r->size());
    return r;
  }

  std::shared_ptr<Region> RegionManager::find_free_region(size_t size) {
    auto list_idx = get_freelist_idx(size);

    while(list_idx < freelists.size()) {
      auto rit = std::find_if(freelists[list_idx].begin(), freelists[list_idx].end(),
         [size](const std::shared_ptr<Region>& a)
         { assert(a != nullptr); return a->size() >= size; });
      if(rit != freelists[list_idx].end()) {
        auto r = *rit;
        freelists[list_idx].erase(rit);
        return r;
      }
      list_idx++;
    }
    return nullptr;
  }

  std::shared_ptr<Region> RegionManager::find_region(const void *host_p) const {
    auto r = std::find_if(allocated_regions.begin(), allocated_regions.end(),
         [host_p](const std::shared_ptr<Region>& a)
         { return a->contains_address(host_p); });
    if(r == allocated_regions.end()) {
      return nullptr;
    }
    return *r;
  }

  std::shared_ptr<Region> RegionManager::find_region(guestptr_t addr) const {
    auto r = std::find_if(allocated_regions.begin(), allocated_regions.end(),
         [addr](const std::shared_ptr<Region>& a)
         { return a->contains_address(addr); });
    if(r == allocated_regions.end()) {
      return nullptr;
    }
    return *r;
  }

  int RegionManager::add_chunk(const size_t size, const std::string &purpose) {
    void *chunk_p;
    const size_t grow_size = size > ELKVM_SYSTEM_MEMGROW ?
      pagesize_align(size) : ELKVM_SYSTEM_MEMGROW;

    int err = pager.create_mem_chunk(&chunk_p, grow_size);
    if(err) {
      printf("LIBELKVM: Could not create memory chunk!\n");
      printf("Errno: %i Msg: %s\n", -err, strerror(-err));
      return err;
    }

    auto idx = get_freelist_idx(grow_size);
    freelists[idx].push_back(std::make_shared<Region>(chunk_p, grow_size, purpose));
    return 0;
  }

  void RegionManager::add_free_region(std::shared_ptr<Region> r) {
    auto list_idx = get_freelist_idx(r->size());
    freelists[list_idx].push_back(r);
  }

  void RegionManager::free_region(std::shared_ptr<Region> r) {
    auto rit = std::find(allocated_regions.begin(), allocated_regions.end(), r);
    assert(rit != allocated_regions.end());
    allocated_regions.erase(rit);

    r->set_free();
    auto list_idx = get_freelist_idx(r->size());
    freelists[list_idx].push_back(r);
  }

  void RegionManager::free_region(void *host_p, const size_t sz) {
    auto rit = std::find_if(allocated_regions.begin(), allocated_regions.end(),
        [host_p](const std::shared_ptr<Region>& a)
        { return a->contains_address(host_p); });

    assert(rit != allocated_regions.end());
    assert((*rit)->contains_address(host_p));
    assert((*rit)->size() == sz);

    auto list_idx = get_freelist_idx(sz);

    (*rit)->set_free();
    freelists[list_idx].push_back(*rit);
    allocated_regions.erase(rit);
  }

  bool RegionManager::host_address_mapped(const void *const p) const {
    for(const auto &r : allocated_regions) {
      if(r->contains_address(p)) {
        return true;
      }
    }
    return false;
  }

  bool RegionManager::same_region(const void *p1, const void *p2) const {
    std::shared_ptr<Region> r = find_region(p1);
    return r->contains_address(p2);
  }

  void RegionManager::use_region(std::shared_ptr<Region> r) {
    assert(r->is_free());
    r->set_used();
    allocated_regions.push_back(r);
  }

  std::array<std::vector<Region>, RegionManager::n_freelists>::size_type
  get_freelist_idx(const size_t size) {
    auto list_idx = 0;
    if(size <= 0x1000) {
      return list_idx = 0;
    } else if(size <= 0x2000) {
      return list_idx = 1;
    } else if(size <= 0x4000) {
      return list_idx = 2;
    } else if(size <= 0x8000) {
      return list_idx = 3;
    } else if(size <= 0x10000) {
      return list_idx = 4;
    } else if(size <= 0x20000) {
      return list_idx = 5;
    } else if(size <= 0x40000) {
      return list_idx = 6;
    } else if(size <= 0x80000) {
      return list_idx = 7;
    } else if(size <= 0x100000) {
      return list_idx = 8;
    } else if(size <= 0x200000) {
      return list_idx = 9;
    } else if(size <= 0x400000) {
      return list_idx = 10;
    } else if(size <= 0x800000) {
      return list_idx = 11;
    } else if(size <= 0x1000000) {
      return list_idx = 12;
    } else if(size <= 0x2000000) {
      return list_idx = 13;
    } else if(size <= 0x4000000) {
      return list_idx = 14;
    } else if(size <= 0x8000000) {
      return list_idx = 15;
    } else {
      return list_idx = 16;
    }
  }

//namespace Elkvm
}


