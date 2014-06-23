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
    region->set_guest_addr(addr);

    host_p = region->base_address();
    if(addr == 0x0) {
      addr = reinterpret_cast<guestptr_t>(host_p);
    }

    mapped_pages = pages_from_size(length);
    map_self();
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
      mapped_pages = pages_from_size(length);
      map_self();
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

  Mapping Mapping::slice_center(off_t off, size_t len, int new_fd, off_t new_offset) {
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
    std::shared_ptr<Region> r = Elkvm::rm.allocate_region(len);

    Mapping mid(r, addr + off, len, prot, flags, new_fd, new_offset, pager);
    if(!mid.anonymous()) {
      mid.fill();
    }

    if(length > off + len) {
      size_t rem = length - off - len;
      r = rm.find_region(reinterpret_cast<char *>(host_p) + off + len);
      Mapping end(r, addr + off + len,
          rem, prot, flags, fd, offset, pager);
      Elkvm::rm.add_mapping(end);
    }

    length = off;
    /* XXX only if the mapping is still fully mapped! */
    mapped_pages = pages_from_size(length);

    return mid;
  }

  void Mapping::sync_guest_to_host_addr() {
    addr = reinterpret_cast<guestptr_t>(host_p);
    region->set_guest_addr(addr);
  }

  int Mapping::fill() {
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
    os << "MAPPING: 0x" << std::hex << mapping.guest_address()
      << "(" << mapping.base_address() << ") length: 0x" << mapping.get_length()
      << "pages mapped: 0x" << mapping.get_pages() << std::endl;
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
