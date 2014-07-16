#include <errno.h>
#include <algorithm>
#include <iostream>

#include <elkvm.h>
#include <elkvm-internal.h>
#include <elfloader.h>
#include <heap.h>

namespace Elkvm {
  int HeapManager::shrink(guestptr_t newbrk) {
    while(newbrk <= mappings_for_brk.back().guest_address()) {
      int err = unmap(mappings_for_brk.back());
      assert(err == 0);
      mappings_for_brk.pop_back();
    }

    guestptr_t slice_base = newbrk;
    if(!page_aligned(newbrk)) {
      slice_base = next_page(slice_base);
    }

    Mapping &m = mappings_for_brk.back();
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
    Mapping m(*this, _rm, curbrk, sz, PROT_READ | PROT_WRITE, MAP_ANONYMOUS, 0, 0);
    mappings_for_brk.push_back(m);
    return map(m);
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

    if(!mappings_for_brk.back().fits_address(newbrk-1)) {
      curbrk = mappings_for_brk.back().grow_to_fill();
      int err = grow(newbrk);
      if(err) {
        return err;
      }
    }

    curbrk = newbrk;
    return 0;
  }

  bool HeapManager::contains_address(guestptr_t addr) const {
    if(!brk_contains_address(addr)) {
      auto it = std::find_if(mappings_for_mmap.begin(), mappings_for_mmap.end(),
          [addr](const Mapping &m) { return m.contains_address(addr); });
      return it == mappings_for_mmap.end();
    }
    return true;
  }

  Mapping &HeapManager::find_mapping(guestptr_t addr) {
    auto it = std::find_if(mappings_for_brk.begin(), mappings_for_brk.end(),
        [addr](const Mapping &m) { return m.contains_address(addr); });
    if(it == mappings_for_brk.end()) {
      it = std::find_if(mappings_for_mmap.begin(), mappings_for_mmap.end(),
          [addr](const Mapping &m) { return m.contains_address(addr); });
      assert(it != mappings_for_mmap.end());
    }

    return *it;
  }

  Mapping &HeapManager::find_mapping(void *host_p) {
    auto it = std::find_if(mappings_for_brk.begin(), mappings_for_brk.end(),
        [host_p](const Mapping &m) { return m.contains_address(host_p); });
    if(it == mappings_for_brk.end()) {
      it = std::find_if(mappings_for_mmap.begin(), mappings_for_mmap.end(),
          [host_p](const Mapping &m) { return m.contains_address(host_p); });
    }
    assert(it != mappings_for_mmap.end());

    return *it;
  }

  bool HeapManager::address_mapped(guestptr_t addr) const {
    auto it = std::find_if(mappings_for_brk.begin(), mappings_for_brk.end(),
        [addr](const Mapping &m) { return m.contains_address(addr); });
    if(it == mappings_for_brk.end()) {
      it = std::find_if(mappings_for_mmap.begin(), mappings_for_mmap.end(),
          [addr](const Mapping &m) { return m.contains_address(addr); });
      return it == mappings_for_mmap.end();
    } else {
      return true;
    }
  }

  Mapping &HeapManager::get_mapping(guestptr_t addr, size_t length, int prot,
      int flags, int fd, off_t off) {
    /* check if we already have a mapping for that address,
     * if we do, we need to split the old mapping, and replace the contents
     * with whatever the user requested,
     * however if we have an exact match, we need to return that */
    auto it = std::find_if(mappings_for_mmap.begin(), mappings_for_mmap.end(),
        [addr, length, prot, flags, fd, off](const Mapping &m)
        { return m.guest_address() == addr
              && m.get_length() == length; });
    if(it == mappings_for_mmap.end()) {
      it = std::find_if(mappings_for_mmap.begin(), mappings_for_mmap.end(),
          [addr](const Mapping &m) { return m.contains_address(addr); });
      if(it != mappings_for_mmap.end()) {
        /* TODO this should be done after we get back to the user! */
        /* this mapping needs to be split! */
        it->slice(addr, length);
      }
      mappings_for_mmap.emplace_back(*this, _rm, addr, length, prot, flags, fd, off);
      Mapping &mapping = mappings_for_mmap.back();
      int err = map(mapping);
      assert(err == 0);

      return mapping;
    }

    /* if we have an exact match, we only need to update this mapping's protection
     * and flags etc. and return the mapping object */
    it->modify(prot, flags, fd, off);
    return *it;
  }

  void HeapManager::add_mapping(const Mapping &mapping) {
    mappings_for_mmap.push_back(mapping);
  }

  void HeapManager::free_mapping(Mapping &mapping) {
    auto it = std::find(mappings_for_brk.begin(), mappings_for_brk.end(), mapping);
    if(it == mappings_for_brk.end()) {
      it = std::find(mappings_for_mmap.begin(), mappings_for_mmap.end(), mapping);
      assert(it != mappings_for_mmap.end());
      //mappings_for_mmap.erase(it);
    } else {
      //mappings_for_brk.erase(it);
    }
  }


  int HeapManager::init(std::shared_ptr<Region> data, size_t sz) {
    assert(mappings_for_brk.empty() && "heap must not be initialized after use");
    /* XXX sz might be wrong here! */
    mappings_for_brk.emplace_back(*this, _rm, data, data->guest_address(), sz, PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS, 0, 0);

    curbrk = next_page(data->guest_address() + sz);
    assert(data->contains_address(curbrk - 1) && "initial brk address must be in data region");

    return 0;
  }

  void HeapManager::dump_mappings() const {
    std::cout << "DUMPING ALL MAPPINGS:\n";
    std::cout << "====================\n";
    for(const auto &reg : mappings_for_brk) {
      print(std::cout, reg);
    }
    for(const auto &reg : mappings_for_mmap) {
      print(std::cout, reg);
    }

    std::cout << std::endl << std::endl;
  }

  int HeapManager::map(Mapping &m) const {
    if(!m.readable() && !m.writeable() && !m.executable()) {
      _rm.get_pager().unmap_region(m.guest_address(), m.get_pages());
      m.set_unmapped();
      return 0;
    }

    ptopt_t opts = 0;
    if(m.writeable()) {
      opts |= PT_OPT_WRITE;
    }
    if(m.executable()) {
      opts |= PT_OPT_EXEC;
    }

    /* add page table entries according to the options specified by the monitor */
    int err = _rm.get_pager().map_region(m.base_address(), m.guest_address(),
        m.get_pages(), opts);
    assert(err == 0);
    return err;
  }

  int HeapManager::unmap(Mapping &m) {
    return unmap(m, m.guest_address(), m.get_pages());
  }

  int HeapManager::unmap(Mapping &m, guestptr_t unmap_addr, unsigned pages) {
    assert(m.contains_address(unmap_addr));
    assert(pages <= m.get_pages());
    assert(m.contains_address(unmap_addr + ((pages-1) * ELKVM_PAGESIZE)));

    int err = _rm.get_pager().unmap_region(unmap_addr, pages);
    assert(err == 0 && "could not unmap this mapping");
    m.pages_unmapped(pages);

    if(m.get_pages() == 0) {
      _rm.free_region(m.get_region());
      free_mapping(m);
    }

    return 0;
  }

  //namespace Elkvm
}
