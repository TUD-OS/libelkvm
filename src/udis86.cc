#include <elkvm/config.h>
#include <elkvm/elkvm.h>
#include <elkvm/elkvm-udis86.h>
#include <elkvm/vcpu.h>

#include <iostream>

#ifdef HAVE_LIBUDIS86
#include <udis86.h>
#endif

namespace Elkvm {


std::ostream &print_code(std::ostream &os, const VM &vm, const VCPU &vcpu) {
  return print_code(os, vm, vcpu.get_reg(Elkvm::Reg_t::rip));
}

std::ostream &print_code(std::ostream &os __attribute__((unused)),
    const VM &vm __attribute__((unused)),
    guestptr_t addr __attribute__((unused))) {
#ifdef HAVE_LIBUDIS86

  const uint8_t *host_p = static_cast<const uint8_t *>(
      vm.get_region_manager()->get_pager().get_host_p(addr));
  assert(host_p != nullptr);

  UDis ud(host_p);

  os << "\n Code:\n"
     <<   " -----\n";
  while(ud.disassemble()) {
    os << " " << ud.next_insn() << std::endl;
  }
  os << std::endl;
#else
  os << "Printing code needs libudis86\n\n";
#endif
  return os;
}

//namespace Elkvm
}
