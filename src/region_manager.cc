#include "region.h"

#include <algorithm>
#include <memory>
#include <iostream>

namespace Elkvm {

  std::shared_ptr<Region> RegionManager::allocate_region(size_t size) {
    auto r = find_free_region(size);

    if(r == nullptr) {
      int err = add_chunk(size);
      assert(err == 0 && "could not allocate memory for new region");

      r = find_free_region(size);
      assert(r != nullptr && "should have free region after allocation");
    }

    if(r->size() > size) {
      auto new_region = r->slice_begin(size);
      add_free_region(r);
      r = new_region;
    }

    assert(r->is_free());
    r->set_used();
    allocated_regions.push_back(r);

    assert(size <= r->size());
    return r;
  }

  std::shared_ptr<Region> RegionManager::find_free_region(size_t size) {
    auto list_idx = get_freelist_idx(size);

    while(list_idx < freelists.size()) {
      auto rit = std::find_if(freelists[list_idx].begin(), freelists[list_idx].end(),
         [size](std::shared_ptr<Region> a)
         { return a->size() >= size; });
      if(rit != freelists[list_idx].end()) {
        auto r = *rit;
        freelists[list_idx].erase(rit);
        return r;
      }
      list_idx++;
    }
    return nullptr;
  }

  std::shared_ptr<Region> RegionManager::find_region(const void *host_p) {
    auto r = std::find_if(allocated_regions.begin(), allocated_regions.end(),
         [host_p](std::shared_ptr<Region> a)
         { return a->contains_address(host_p); });
    assert(r != allocated_regions.end() && "no region found for given host pointer");
    return *r;
  }

  int RegionManager::add_chunk(const size_t size) {
    assert(pager != NULL && "must have pager to add chunks to region");

    void *chunk_p;
    const size_t grow_size = size > ELKVM_SYSTEM_MEMGROW ?
      pagesize_align(size) : ELKVM_SYSTEM_MEMGROW;

    int err = elkvm_pager_create_mem_chunk(pager, &chunk_p, grow_size);
    if(err) {
      printf("LIBELKVM: Could not create memory chunk!\n");
      printf("Errno: %i Msg: %s\n", -err, strerror(-err));
      return err;
    }

    assert(grow_size <= 0x8000000 && grow_size > 0x400000);
    freelists[15].push_back(std::make_shared<Region>(chunk_p, grow_size));
    return 0;
  }

  void RegionManager::add_system_chunk() {
    auto list_idx = get_freelist_idx(pager->system_chunk.memory_size);
    freelists[list_idx].push_back(
        std::make_shared<Region>(
        reinterpret_cast<void *>(pager->system_chunk.userspace_addr),
        pager->system_chunk.memory_size));
  }

  void RegionManager::add_free_region(std::shared_ptr<Region> r) {
    auto list_idx = get_freelist_idx(r->size());
    freelists[list_idx].push_back(r);
  }

  void RegionManager::free_region(std::shared_ptr<Region> r) {
    auto rit = std::find(allocated_regions.begin(), allocated_regions.end(), r);
    assert(rit != allocated_regions.end());
    allocated_regions.erase(rit);

    auto list_idx = get_freelist_idx(r->size());
    freelists[list_idx].push_back(r);
  }

  void RegionManager::free_region(void *host_p, const size_t sz) {
    auto rit = std::find_if(allocated_regions.begin(), allocated_regions.end(),
        [host_p](std::shared_ptr<Region> a)
        { return a->contains_address(host_p); });

    assert(rit != allocated_regions.end());
    assert((*rit)->contains_address(host_p));
    assert((*rit)->size() == sz);

    auto list_idx = get_freelist_idx(sz);
    /* emplace a new region in the appropriate freelist, which is then automatically
     * marked as free */
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

  std::array<std::vector<Region>, 16>::size_type
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
    }

    assert(false && "request larger than ELKVM_GROW_SIZE");
    /* TODO requests larger than ELKVM_GROW_SIZE */
  }

//namespace Elkvm
}


