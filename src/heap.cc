#include <errno.h>
#include <algorithm>
#include <iostream>

#include <elkvm.h>
#include <heap.h>
#include <region-c.h>
#include <elfloader.h>

namespace Elkvm {
  HeapManager heap_m;

  int HeapManager::shrink(guestptr_t newbrk) {
    while(newbrk <= mappings.back().guest_address()) {
      int err = mappings.back().unmap_self();
      assert(err == 0);
      mappings.pop_back();
    }

    guestptr_t slice_base = newbrk;
    if(!page_aligned(newbrk)) {
      slice_base = next_page(slice_base);
    }

    Mapping &m = mappings.back();
    if(m.guest_address() + m.get_length() == slice_base) {
      return 0;
    }

    assert(m.guest_address() + m.get_length() > slice_base);
    size_t len = m.guest_address() + m.get_length() - slice_base;
    m.slice(slice_base, len);
    return 0;
  }

  int HeapManager::grow(guestptr_t newbrk) {
    assert(newbrk > curbrk);
    size_t sz = newbrk - curbrk;
    Mapping m(curbrk, sz, PROT_READ | PROT_WRITE, MAP_ANONYMOUS, 0, 0);
    mappings.push_back(m);
    return m.map_self();
  }

  int HeapManager::brk(guestptr_t newbrk) {
    if(newbrk < curbrk) {
      int err = shrink(newbrk);
      if(err) {
        return err;
      }
      curbrk = newbrk;
      return 0;
    }

    if(!mappings.back().fits_address(newbrk-1)) {
      curbrk = mappings.back().grow_to_fill();
      int err = grow(newbrk);
      if(err) {
        return err;
      }
    }

    curbrk = newbrk;
    return 0;
  }

  Mapping &HeapManager::find_mapping(guestptr_t addr) {
    auto it = std::find_if(mappings.begin(), mappings.end(),
        [addr](const Mapping &m) { return m.contains_address(addr); });
    assert(it != mappings.end());

    return *it;
  }

  int HeapManager::init(std::shared_ptr<Region> data, size_t sz) {
    assert(mappings.empty() && "heap must not be initialized after use");
    /* XXX sz might be wrong here! */
    mappings.emplace_back(data, data->guest_address(), sz, PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS, 0, 0);

    curbrk = next_page(data->guest_address() + sz);
    assert(data->contains_address(curbrk - 1) && "initial brk address must be in data region");

    return 0;
  }

  //namespace Elkvm
}

void elkvm_init_heap_manager(struct kvm_pager *const pager) {
  Elkvm::heap_m.set_pager(pager);
}
