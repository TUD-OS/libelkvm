#include <cstring>
#include <vector>

#include <elkvm.h>
#include <elkvm-internal.h>
#include <mapping.h>
#include <region.h>

namespace Elkvm {
  Mapping::Mapping(std::shared_ptr<Region> r,
      guestptr_t guest_addr, size_t l, int pr, int f, int fdes, off_t off) :
    addr(guest_addr),
    length(l),
    prot(pr),
    flags(f),
    fd(fdes),
    offset(off),
    region(r)
  {
      assert(region->size() >= length);

      host_p = region->base_address();
      if(addr == 0x0) {
        addr = reinterpret_cast<guestptr_t>(host_p);
      }
      region->set_guest_addr(addr);
      assert(!region->is_free());
      mapped_pages = pages_from_size(length);
  }

  guestptr_t Mapping::grow_to_fill() {
    addr = region->guest_address();
    length = region->size();
    mapped_pages = pages_from_size(length);
    return addr + length;
  }

  std::shared_ptr<Region> Mapping::move_guest_address(off64_t off) {
    assert(off > 0);
    assert(off < length);
    addr += off;
    length -= off;
    mapped_pages = pages_from_size(length);
    host_p = reinterpret_cast<char *>(host_p) + off;
    return region->slice_begin(off);
  }

  void Mapping::set_length(size_t len) {
    assert(length >= len);
    length = len;
    mapped_pages = pages_from_size(length);
  }

  void Mapping::modify(int pr, int fl, int filedes, off_t o) {
    mapped_pages = pages_from_size(length);

    if(pr != prot) {
      prot = pr;
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

  void Mapping::mprotect(int pr) {
    prot = pr;
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
    host_p = mapping->host_p;
    addr   = mapping->guest_virt;
    region->set_guest_addr(addr);
    length = mapping->length;
    mapped_pages = pages_from_size(length);
    prot  = mapping->prot;

    if(flags != mapping->flags || fd != mapping->fd || offset != mapping->offset) {
      flags = mapping->flags;
      fd   = mapping->fd;
      offset = mapping->offset;
      fill();
    }
  }

  int Mapping::diff(struct region_mapping *mapping) const {
    assert(host_p == mapping->host_p && "changing the mapping's host address is not yet supported");
    if(host_p != mapping->host_p
        || addr != mapping->guest_virt
        || length != mapping->length
        || prot != mapping->prot) {
      return 1;
    }

    return 0;
  }

  size_t Mapping::grow(size_t sz) {
    if(sz <= length) {
      return length;
    }

    if(sz >= region->size()) {
      length = region->size();
    } else {
      length = sz;
    }
    return length;
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
