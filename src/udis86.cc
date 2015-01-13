#include <elkvm/elkvm.h>
#include <elkvm/elkvm-udis86.h>
#include <elkvm/vcpu.h>

#include <iostream>

#ifdef HAVE_LIBUDIS86
#include <udis86.h>
#endif

namespace Elkvm {

#ifdef HAVE_LIBUDIS86
int get_next_code_byte(const VM &vm, VCPU &vcpu, guestptr_t guest_addr) {
  assert(guest_addr != 0x0);

  const uint8_t *host_p = static_cast<const uint8_t *>(
      vm.get_region_manager()->get_pager().get_host_p(guest_addr));
  assert(host_p != nullptr);

  const size_t disassembly_size = 40;
  ud_set_input_buffer(&vcpu.ud_obj, host_p, disassembly_size);

  return 0;
}

void init_udis86(VCPU &vcpu) {
  const auto bits = 64;
  ud_init(&vcpu.ud_obj);
  ud_set_mode(&vcpu.ud_obj, bits);
  ud_set_syntax(&vcpu.ud_obj, UD_SYN_INTEL);
}
#endif

std::ostream &print_code(std::ostream &os, const VM &vm, VCPU &vcpu) {
  return print_code(os, vm, vcpu, vcpu.get_reg(Elkvm::Reg_t::rip));
}

std::ostream &print_code(std::ostream &os __attribute__((unused)),
    const VM &vm __attribute__((unused)),
    VCPU &vcpu __attribute__((unused)),
    guestptr_t addr __attribute__((unused))) {
#ifdef HAVE_LIBUDIS86
  int err = get_next_code_byte(vm, vcpu, addr);
  if(err) {
    os << "Error in get_next_code_byte();\n";
    return os;
  }

  os << "\n Code:\n"
     <<   " -----\n";
  while(ud_disassemble(&vcpu.ud_obj)) {
    os << " " << ud_insn_asm(&vcpu.ud_obj) << std::endl;
  }
  os << std::endl;
#endif
  return os;
}

//namespace Elkvm
}
