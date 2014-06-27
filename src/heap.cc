#include <errno.h>
#include <iostream>

#include <elkvm.h>
#include <heap.h>
#include <region-c.h>
#include <elfloader.h>

namespace Elkvm {
  extern RegionManager rm;
  HeapManager heap_m;

  int HeapManager::shrink(guestptr_t newbrk) {
    while(newbrk <= mappings.back().guest_address()) {
      mappings.pop_back();
    }

    guestptr_t slice_base = newbrk;
    if(!page_aligned(newbrk)) {
      slice_base = next_page(slice_base);
    }
    Mapping &m = mappings.back();
    assert(m.guest_address() + m.get_length() > slice_base);
    size_t len = m.guest_address() + m.get_length() - slice_base;
    m.slice(slice_base, len);
    return 0;
  }

  int HeapManager::grow(guestptr_t newbrk) {
    size_t sz = newbrk - curbrk;
    Mapping m(curbrk, sz, PROT_READ | PROT_WRITE, MAP_ANONYMOUS, 0, 0, pager);
    mappings.push_back(m);
    return m.map_self();
  }

  int HeapManager::brk(guestptr_t newbrk) {
    if(newbrk < curbrk) {
      int err = shrink(newbrk);
      if(err) {
        return err;
      }
      return 0;
    }

    if(!mappings.back().contains_address(newbrk-1)) {
      int err = grow(newbrk);
      if(err) {
        return err;
      }
    }

    curbrk = newbrk;
    return 0;
  }

  int HeapManager::init(std::shared_ptr<Region> data, size_t sz) {
    assert(heap_regions.empty() && "heap must not be initialized after use");

    heap_regions.push_back(data);
    curbrk = next_page(data->guest_address() + sz);
    assert(data->contains_address(curbrk - 1) && "initial brk address must be in data region");

    return 0;
  }

  //namespace Elkvm
}

int elkvm_heap_initialize(struct elkvm_memory_region *region, uint64_t size) {
  assert(region != NULL);

  auto r = Elkvm::rm.find_region(region->host_base_p);
  r->set_guest_addr(region->guest_virtual);
  return Elkvm::heap_m.init(r, size);

}

void elkvm_init_heap_manager(struct kvm_pager *const pager) {
  Elkvm::heap_m.set_pager(pager);
}
