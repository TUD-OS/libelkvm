//
// libelkvm - A library that allows execution of an ELF binary inside a virtual
// machine without a full-scale operating system
// Copyright (C) 2013-2015 Florian Pester <fpester@os.inf.tu-dresden.de>, Björn
// Döbel <doebel@os.inf.tu-dresden.de>,   economic rights: Technische Universitaet
// Dresden (Germany)
//
// This file is part of libelkvm.
//
// libelkvm is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// libelkvm is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with libelkvm.  If not, see <http://www.gnu.org/licenses/>.
//

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

  os << "\n Code (from 0x" << std::hex << addr << "):\n"
     <<   " ------------------------------\n";
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
