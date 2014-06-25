#include <mapping.h>
#include <region.h>
#include <elkvm.h>

namespace Elkvm {
  extern RegionManager rm;

  Mapping::Mapping(guestptr_t guest_addr, size_t l, int pr, int f,
      int fdes, off_t off, struct kvm_pager * pa)
    : addr(guest_addr),
      length(l),
      prot(pr),
      flags(f),
      fd(fdes),
      offset(off),
      pager(pa) {

    region = Elkvm::rm.allocate_region(length);
    assert(!region->is_free());

    host_p = region->base_address();
    if(addr == 0x0) {
      addr = reinterpret_cast<guestptr_t>(host_p);
    }
    region->set_guest_addr(addr);

    mapped_pages = pages_from_size(length);
  }

  Mapping::Mapping(std::shared_ptr<Region> r, guestptr_t guest_addr, size_t l, int pr, int f,
          int fdes, off_t off, struct kvm_pager * pa) :
    region(r),
    addr(guest_addr),
    length(l),
    prot(pr),
    flags(f),
    fd(fdes),
    offset(off),
    pager(pa) {
      host_p = region->base_address();
      region->set_guest_addr(addr);
      assert(!region->is_free());
      mapped_pages = pages_from_size(length);
  }

  int Mapping::map_self() {
    ptopt_t opts = 0;
    if(writeable()) {
      opts |= PT_OPT_WRITE;
    }
    if(executable()) {
      opts |= PT_OPT_EXEC;
    }

    /* add page table entries according to the options specified by the monitor */
    int err = elkvm_pager_map_region(pager, host_p, addr, mapped_pages, opts);
    return err;
  }

  int Mapping::unmap(guestptr_t unmap_addr, unsigned pages) {
    assert(contains_address(unmap_addr));
    assert(pages <= mapped_pages);

    //TODO use elkvm_pager_unmap_region here again!
    guestptr_t cur_addr_p = unmap_addr;
    while(pages) {
      int err = elkvm_pager_destroy_mapping(pager, cur_addr_p);
      assert(err == 0);
      cur_addr_p += ELKVM_PAGESIZE;
      pages--;
    }
    mapped_pages -= pages;

    if(mapped_pages == 0) {
      Elkvm::rm.free_region(region);
      Elkvm::rm.free_mapping(*this);
    }

    return 0;
  }

  bool Mapping::contains_address(void *p) {
    return (host_p <= p) && (p < (reinterpret_cast<char *>(host_p) + length));
  }

  bool Mapping::contains_address(guestptr_t a) {
    return (addr <= a) && (a < (addr + length));
  }

  void Mapping::slice(guestptr_t slice_base, size_t len) {
    assert(contains_address(slice_base)
        && "slice address must be contained in mapping");

    if(slice_base == addr) {
      assert(false && "slice begin not implemented!");
    }

    /* slice_base is now always larger than host_p */
    off_t off = slice_base - addr;

    if(contains_address(slice_base + len)) {
      /* slice_center also includes the case that the end of the sliced region
       * is the end of this region */
      slice_center(off, len);
    } else {
      /* slice_end is only needed, when we want to expand the new region beyond
       * the end of this region */
      slice_end(slice_base, len);
    }
  }

  void Mapping::slice_center(off_t off, size_t len) {

    assert(contains_address(reinterpret_cast<char *>(host_p) + off + len));
    assert(0 <= off < length);

    /* unmap the old stuff */
    for(guestptr_t current_addr = addr + off;
        current_addr < addr + off + len;
        current_addr += ELKVM_PAGESIZE) {
      int err = elkvm_pager_destroy_mapping(pager, current_addr);
      assert(err == 0);
    }

    region->slice_center(off, len);

    if(length > off + len) {
      size_t rem = length - off - len;
      auto r = rm.find_region(reinterpret_cast<char *>(host_p) + off + len);

      /* There should be no need to process this mapping any further, because we
       * feed it the split memory region, with the old data inside */
      Mapping end(r, addr + off + len,
          rem, prot, flags, fd, offset + off + len, pager);
      Elkvm::rm.add_mapping(end);
    }

    length = off;
    /* XXX only if the mapping is still fully mapped! */
    mapped_pages = pages_from_size(length);
  }

  void Mapping::slice_end(guestptr_t slice_base, size_t len) {
    /* unmap the old stuff */
    for(guestptr_t current_addr = slice_base;
        current_addr < addr + length;
        current_addr += ELKVM_PAGESIZE) {
      int err = elkvm_pager_destroy_mapping(pager, current_addr);
      assert(err == 0);
      mapped_pages--;
    }

    length = length - ((addr + length) - slice_base);

    /* TODO free part of the attached memory region */

  }

  int Mapping::fill() {
    assert(fd > 0 && "cannot fill mapping without file descriptor");

    off_t pos = lseek(fd, 0, SEEK_CUR);
    assert(pos >= 0 && "could not get current file position");

    int err = lseek(fd, offset, SEEK_SET);
    assert(err >= 0 && "seek set in pass_mmap failed");

    char *buf = reinterpret_cast<char *>(host_p);
    ssize_t bytes = 0;
    size_t total = 0;
    errno = 0;
    while((total <= length)
        && (bytes = read(fd, buf, length - total)) > 0) {
      assert(bytes >= 0);
      buf += bytes;
      total += bytes;
    }

    ssize_t rem = length - total;
    if(rem > 0) {
//      printf("read %zd bytes of %zd bytes\n", total, length);
//      printf("\nzeroing out %zd bytes at %p\n", rem, buf);
      memset(buf, 0, rem);
    }
    err = lseek(fd, pos, SEEK_SET);
    assert(err >= 0 && "could not restore file position");
    return err;
  }

  void Mapping::sync_back(struct region_mapping *mapping) {
    /* TODO if the host_p is set we need to change pt entries
     *      same for the guest_address */
    host_p = mapping->host_p;
    addr   = mapping->guest_virt;
    length = mapping->length;
    /* TODO if prot changed we need to update pt entries as well */
    prot  = mapping->prot;
    flags = mapping->flags;
    /* TODO if flags, fd or offset changed we need to refill the mapping */
    fd   = mapping->fd;
    offset = mapping->offset;

  }

  std::ostream &print(std::ostream &os, const Mapping &mapping) {
    if(mapping.anonymous()) {
      os << "ANONYMOUS ";
    }
    os << "MAPPING: 0x" << std::hex << mapping.guest_address()
      << " (" << mapping.base_address() << ") length: 0x" << mapping.get_length()
      << " pages mapped: 0x" << mapping.get_pages();
    if(!mapping.anonymous()) {
      os << " fd: " << mapping.get_fd();
    }
    os << std::endl;
    return os;
  }

  struct region_mapping *Mapping::c_mapping() {
    struct region_mapping *mapping = new(struct region_mapping);
    mapping->host_p = host_p;
    mapping->guest_virt = addr;
    mapping->length = length;
    mapping->mapped_pages = mapped_pages;
    mapping->prot = prot;
    mapping->flags = flags;
    mapping->fd = fd;
    mapping->offset = offset;
    return mapping;
  }

  bool operator==(const Mapping &m1, const Mapping &m2) {
    return m1.base_address() == m2.base_address()
      && m1.guest_address() == m2.guest_address()
      && m1.get_length() == m2.get_length()
      && m1.get_pages() == m2.get_pages()
      && m1.anonymous() == m2.anonymous()
      && m1.writeable() == m2.writeable()
      && m1.executable() == m2.executable()
      && m1.get_fd() == m2.get_fd()
      && m1.get_offset() == m2.get_offset();
  }

//namespace Elkvm
}
