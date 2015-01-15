#include <elkvm/elkvm.h>
#include <elkvm/elkvm-log.h>
#include <elkvm/mapping.h>
#include <elkvm/syscall.h>

namespace Elkvm {

void slice_and_recreate(VM *vmi, Mapping &mapping, guestptr_t addr, size_t len, int prot) {
  auto flags = mapping.get_flags();
  auto fd = mapping.get_fd();
  auto off = mapping.get_offset();
  /* we need to split this mapping */
  vmi->get_heap_manager().slice(mapping, addr, len);
  vmi->get_heap_manager().create_mapping(addr, len, prot, flags, fd, off);
}

//namespace Elkvm
}

long elkvm_do_mprotect(Elkvm::VM * vmi) {
  guestptr_t addr = 0;
  CURRENT_ABI::paramtype len = 0;
  CURRENT_ABI::paramtype prot = 0;
  vmi->unpack_syscall(&addr, &len, &prot);

  assert(page_aligned<guestptr_t>(addr) && "mprotect address must be page aligned");
  if(!vmi->get_heap_manager().address_mapped(addr)) {
    vmi->get_heap_manager().dump_mappings();
    vmi->get_region_manager()->dump_regions();
    INFO() <<"mprotect with invalid address: 0x" << std::hex
      << addr << std::endl;
    return -EINVAL;
  }

  Elkvm::Mapping &mapping = vmi->get_heap_manager().find_mapping(addr);
  int err = 0;

  assert(mapping.get_length() >= len);
  if(mapping.get_length() != len) {
    /* this will invalidate the mapping ref! */
    slice_and_recreate(vmi, mapping, addr, len, prot);
  } else {
    /* only modify this mapping */
    mapping.mprotect(prot);
    err = vmi->get_heap_manager().map(mapping);
  }

  if(vmi->debug_mode()) {
    DBG() << "MPROTECT requested with address 0x"
          << std::hex << addr
          << " len: 0x" << len
          << " prot: 0x" << prot;
    print(std::cout, mapping);
    DBG() << "RESULT: " << err;
  }

  return err;
}
