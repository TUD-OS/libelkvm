#include <errno.h>
#include <iostream>

#include <elkvm.h>
#include <heap.h>
#include <region-c.h>
#include <elfloader.h>

namespace Elkvm {
  extern RegionManager rm;
  HeapManager heap_m;

  int HeapManager::map_heap(guestptr_t newbrk, off64_t off) {
    guestptr_t map_addr = 0x0;
    if(page_aligned(curbrk)) {
      map_addr = curbrk;
    } else {
      map_addr = next_page(curbrk);
    }

    auto heap_top = heap_regions.back();
    void *host_p = reinterpret_cast<char *>(heap_top->base_address()) + off;
    if(heap_top->guest_address() == 0x0) {
      heap_top->set_guest_addr(map_addr);
    }
    while(map_addr < newbrk) {
      assert(host_p < heap_top->last_valid_address());
      int err = elkvm_pager_create_mapping(pager, host_p, map_addr, PT_OPT_WRITE);
      if(err) {
        return err;
      }

      map_addr = map_addr + ELKVM_PAGESIZE;
      host_p = reinterpret_cast<char *>(host_p) + ELKVM_PAGESIZE;
    }

    return 0;
  }

  int HeapManager::shrink(guestptr_t newbrk) {
    auto heap_top = heap_regions.back();
    while(newbrk <= heap_top->guest_address()) {
      rm.free_region(heap_top);
      heap_regions.pop_back();
      heap_top = heap_regions.back();
    }

    guestptr_t unmap_addr = page_aligned(curbrk) ? curbrk - ELKVM_PAGESIZE : curbrk;
    guestptr_t unmap_end = page_aligned(newbrk) ? newbrk : next_page(newbrk);




    for(guestptr_t guest_addr = unmap_addr;
        guest_addr >= unmap_end;
        guest_addr -= ELKVM_PAGESIZE) {



      int err = elkvm_pager_destroy_mapping(pager, guest_addr);
      if(err) {
        return err;
      }
    }

    curbrk = newbrk;
    return 0;
  }

  int HeapManager::grow(guestptr_t newbrk) {
    size_t sz = newbrk - curbrk;
    std::shared_ptr<Region> r = rm.allocate_region(sz);
    if(r == nullptr) {
      return -ENOMEM;
    }
    assert(r->size() >= sz && "allocated region must be suitable in size!");

    heap_regions.push_back(r);

    return map_heap(newbrk, 0);
  }

  int HeapManager::grow_in_region(guestptr_t newbrk) {
    auto heap_top = heap_regions.back();

    assert(curbrk >= heap_top->guest_address());
    assert(heap_top->contains_address(curbrk - 1)
        && "current brk address must be inside current heap region");

    off64_t newbrk_offset = heap_top->offset_in_region(curbrk);
    if(!page_aligned(curbrk)) {
      newbrk_offset = next_page(newbrk_offset);
    }

    int err = map_heap(newbrk, newbrk_offset);
    return err;
  }

  int HeapManager::brk(guestptr_t newbrk) {
    int err;

    if(newbrk < curbrk) {
      return shrink(newbrk);
    }

    if(address_in_heap_region(newbrk-1)) {
      err = grow_in_region(newbrk);
    } else {
      guestptr_t tmpbrk = last_heap_address() + 1;
      err = grow_in_region(tmpbrk);
      assert(err == 0);

      curbrk = tmpbrk;
      err = grow(newbrk);
    }

    if(err) {
      return err;
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
