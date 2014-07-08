#include <mapping.h>
#include <region.h>
#include <elkvm.h>

namespace Elkvm {
  extern std::unique_ptr<RegionManager> rm;

  Mapping::Mapping(guestptr_t guest_addr, size_t l, int pr, int f,
      int fdes, off_t off)
    : addr(guest_addr),
      length(l),
      prot(pr),
      flags(f),
      fd(fdes),
      offset(off) {

    region = Elkvm::rm->allocate_region(length);
    assert(!region->is_free());

    host_p = region->base_address();
    if(addr == 0x0) {
      addr = reinterpret_cast<guestptr_t>(host_p);
    }
    region->set_guest_addr(addr);
    mapped_pages = pages_from_size(length);
  }

  Mapping::Mapping(std::shared_ptr<Region> r, guestptr_t guest_addr, size_t l, int pr, int f,
          int fdes, off_t off) :
    addr(guest_addr),
    length(l),
    prot(pr),
    flags(f),
    fd(fdes),
    offset(off),
    region(r) {
      assert(region->size() >= length);
      host_p = region->base_address();
      region->set_guest_addr(addr);
      assert(!region->is_free());
      mapped_pages = pages_from_size(length);
  }

  guestptr_t Mapping::grow_to_fill() {
    addr = region->guest_address();
    length = region->size();
    mapped_pages = pages_from_size(length);
    map_self();
    return addr + length;
  }

  int Mapping::map_self() {
    if(!readable() && !writeable() && !executable()) {
      rm->get_pager().unmap_region(addr, mapped_pages);
      mapped_pages = 0;
      return 0;
    }

    ptopt_t opts = 0;
    if(writeable()) {
      opts |= PT_OPT_WRITE;
    }
    if(executable()) {
      opts |= PT_OPT_EXEC;
    }

    /* add page table entries according to the options specified by the monitor */
    int err = rm->get_pager().map_region(host_p, addr, mapped_pages, opts);
    assert(err == 0);
    return err;
  }

  void Mapping::modify(int pr, int fl, int filedes, off_t o) {
    mapped_pages = pages_from_size(length);

    if(pr != prot) {
      prot = pr;
      map_self();
    }
    if(flags != fl) {
      if(anonymous() && !(fl & MAP_ANONYMOUS)) {
        flags = fl;
        fd = filedes;
        offset = o;
        fill();
      }
      flags = fl;
    }
    if(fd != filedes) {
      offset = o;
      fd = filedes;
      if(!anonymous()) {
        fill();
      }
    }
    if(offset != o) {
      offset = o;
      if(!anonymous()) {
        fill();
      }
    }
  }

  int Mapping::mprotect(int pr) {
    if(pr != prot) {
      prot = pr;
      return map_self();
    }
    return 0;
  }

  int Mapping::unmap(guestptr_t unmap_addr, unsigned pages) {
    assert(contains_address(unmap_addr));
    assert(pages <= mapped_pages);
    assert(contains_address(unmap_addr + ((pages-1) * ELKVM_PAGESIZE)));

    int err = rm->get_pager().unmap_region(unmap_addr, pages);
    assert(err == 0 && "could not unmap this mapping");
    mapped_pages -= pages;

    if(mapped_pages == 0) {
      Elkvm::rm->free_region(region);
      Elkvm::rm->free_mapping(*this);
    }

    return 0;
  }

  bool Mapping::contains_address(void *p) const {
    return (host_p <= p) && (p < (reinterpret_cast<char *>(host_p) + length));
  }

  bool Mapping::contains_address(guestptr_t a) const {
    return (addr <= a) && (a < (addr + length));
  }

  bool Mapping::fits_address(guestptr_t a) const {
    return (region->guest_address()) <= a
        && (a < (region->guest_address() + region->size()));
  }

  void Mapping::slice(guestptr_t slice_base, size_t len) {
    assert(contains_address(slice_base)
        && "slice address must be contained in mapping");
    if(slice_base == addr) {
      slice_begin(len);
      return;
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
      slice_end(slice_base);
    }
  }

  void Mapping::slice_center(off_t off, size_t len) {
    assert(contains_address(reinterpret_cast<char *>(host_p) + off + len));
    assert(0 <= off < length);

    /* unmap the old stuff */
    unsigned pages = pages_from_size(len);
    unmap(addr + off, pages);

    region->slice_center(off, len);

    if(length > off + len) {
      size_t rem = length - off - len;
      auto r = rm->find_region(reinterpret_cast<char *>(host_p) + off + len);
      /* There should be no need to process this mapping any further, because we
       * feed it the split memory region, with the old data inside */
      Mapping end(r, addr + off + len,
          rem, prot, flags, fd, offset + off + len);
      Elkvm::rm->add_mapping(end);
    }

    length = off;
    /* XXX only if the mapping is still fully mapped! */
    mapped_pages = pages_from_size(length);
  }

  void Mapping::slice_begin(size_t len) {
    unsigned pages = pages_from_size(len);
    unmap(addr, pages);

    addr += len;
    length -= len;
    host_p = reinterpret_cast<char *>(host_p) + len;
    auto r = region->slice_begin(len);
    Elkvm::rm->add_free_region(r);
  }

  void Mapping::slice_end(guestptr_t slice_base) {
    assert(contains_address(slice_base));

    /* unmap the old stuff */
    unmap(slice_base, pages_from_size((addr + length) - slice_base));

    assert(((addr + length) - slice_base) < length);
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
    } else {
      os << "          ";
    }

    os << "MAPPING: 0x" << std::hex << mapping.guest_address()
      << " (" << mapping.base_address() << ") length: 0x" << mapping.get_length()
      << " last address: " << mapping.guest_address() + mapping.get_length()
      << " pages mapped: 0x" << mapping.get_pages();
    if(!mapping.anonymous()) {
      os << " fd: " << mapping.get_fd();
    }
    os << " protection: ";
    if(mapping.readable()) {
      os << "R";
    }
    if(mapping.writeable()) {
      os << "W";
    }
    if(mapping.executable()) {
      os << "X";
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
