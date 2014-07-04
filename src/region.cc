#include <iostream>
#include <memory>

#include <inttypes.h>
#include <stdio.h>

#include <elkvm.h>
#include "region.h"
#include "region-c.h"

namespace Elkvm {
  RegionManager rm;

  std::ostream &print(std::ostream &stream, const Region &r) {
    if(r.is_free()) {
      stream << "FREE ";
    }
    stream << std::hex
      <<"REGION[" << &r << "] guest address: 0x" << r.guest_address()
      << " host_p: " << r.base_address() << " size: 0x" << r.size() << std::endl;
    return stream;
  }

  bool same_region(const void *p1, const void *p2) {
    std::shared_ptr<Region> r = Elkvm::rm.find_region(p1);
    return r->contains_address(p2);
  }

  bool operator==(const Region &r, const void *const p) {
    return r.contains_address(p);
  }

  bool operator==(const Region &r1, const Region &r2) {
    return r1.base_address() == r2.base_address()
      && r1.guest_address() == r2.guest_address()
      && r1.size() == r2.size()
      && r1.is_free() == r2.is_free();
  }

  struct elkvm_memory_region *Region::c_region() const {
    struct elkvm_memory_region *r = new(struct elkvm_memory_region);
    r->host_base_p = host_p;
    r->guest_virtual = addr;
    r->region_size = rsize;
    r->used = !free;
    r->grows_downward = 0;
    r->rc = r->lc = NULL;
    return r;
  }

  bool Region::contains_address(const void * const p) const {
    return (host_p <= p) && (p < (reinterpret_cast<char *>(host_p) + rsize));
  }

  bool Region::contains_address(guestptr_t guest_addr) const {
    return (addr <= guest_addr) && (guest_addr < (addr + rsize));
  }

  off64_t Region::offset_in_region(guestptr_t guest_addr) const {
    assert(contains_address(addr) && "address must be in region to calc offset");
    return guest_addr - addr;
  }

  size_t Region::space_after_address(const void * const p) const {
    assert(contains_address(p));
    return reinterpret_cast<char *>(host_p)
      + rsize - reinterpret_cast<const char * const>(p);
  }

  void *Region::last_valid_address() const {
    return reinterpret_cast<char *>(host_p) + rsize;
  }

  guestptr_t Region::last_valid_guest_address() const {
    return addr + rsize - 1;
  }

  std::shared_ptr<Region> Region::slice_begin(const size_t size) {
    //assert(free);
    assert(size > 0x0);
    assert(rsize > pagesize_align(size));

    std::shared_ptr<Region> r =
      std::make_shared<Region>(host_p, pagesize_align(size));

    host_p = reinterpret_cast<char *>(host_p) + r->size();
    rsize  -= r->size();
    if(addr != 0x0) {
      addr += r->size();
    }
    assert(rsize > 0x0);
    assert(r->size() > 0x0);
    return r;
  }

  void Region::slice_center(off_t off, size_t len) {
    assert(contains_address(reinterpret_cast<char *>(host_p) + off + len));
    assert(0 < off <= rsize);

    std::shared_ptr<Region> r = std::make_shared<Region>(
        reinterpret_cast<char *>(host_p) + off + len,
        rsize - off - len);
    r->set_guest_addr(addr + off);

    rsize = off;

    Elkvm::rm.use_region(r);
    Elkvm::rm.add_free_region(std::make_shared<Region>(
          reinterpret_cast<char *>(host_p) + off, len));
    //TODO maybe return ptr to free region?
  }

//namespace Elkvm
}


struct elkvm_memory_region *elkvm_region_create(uint64_t req_size) {
  std::shared_ptr<Elkvm::Region> r = Elkvm::rm.allocate_region(req_size);
  assert(r->size() >= req_size && "allocated region must be suitable in size!");
	return r->c_region();
}

int elkvm_region_free(struct elkvm_memory_region *region) {
  Elkvm::rm.free_region(region->host_base_p, region->region_size);
  delete(region);
  return 0;
}

int elkvm_init_region_manager(struct kvm_pager *const pager) {
  Elkvm::rm.set_pager(pager);
  Elkvm::rm.add_system_chunk();
  return 0;
}

