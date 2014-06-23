#include <mapping.h>
#include <elkvm.h>

namespace Elkvm {

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
