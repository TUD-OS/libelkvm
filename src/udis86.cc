#include <elkvm/config.h>
#include <elkvm/elkvm.h>
#include <elkvm/elkvm-udis86.h>
#include <elkvm/vcpu.h>

#include <iostream>

#ifdef HAVE_LIBUDIS86
#include <udis86.h>
#endif

namespace Elkvm {

UDis::UDis(const uint8_t *ptr) :
  ud_obj() {
 #ifdef HAVE_LIBUDIS86
   ud_init(&ud_obj);
   ud_set_mode(&ud_obj, bits);
   ud_set_syntax(&ud_obj, UD_SYN_INTEL);
   ud_set_input_buffer(&ud_obj, ptr, disassembly_size);
 #else
   (void)ptr;
 #endif
}

int UDis::disassemble() {
 #ifdef HAVE_LIBUDIS86
   return ud_disassemble(&ud_obj);
 #else
   return 0;
 #endif
}

std::string UDis::next_insn() {
 #ifdef HAVE_LIBUDIS86
   return ud_insn_asm(&ud_obj);
 #else
   return "";
 #endif
}

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
