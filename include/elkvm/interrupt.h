/* * libelkvm - A library that allows execution of an ELF binary inside a virtual
 * machine without a full-scale operating system
 * Copyright (C) 2013-2015 Florian Pester <fpester@os.inf.tu-dresden.de>, Björn
 * Döbel <doebel@os.inf.tu-dresden.de>,   economic rights: Technische Universitaet
 * Dresden (Germany)
 *
 * This file is part of libelkvm.
 *
 * libelkvm is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * libelkvm is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libelkvm.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <memory>

#include <elkvm/elkvm.h>
#include <elkvm/vcpu.h>

namespace Elkvm {

namespace Interrupt {
  const int success = 0;
  const int failure = 1;
  namespace Vector {
    const int debug_trap               = 0x01;
    const int stack_segment_fault      = 0x0c;
    const int general_protection_fault = 0x0d;
    const int page_fault               = 0x0e;
  }

  int handle_stack_segment_fault(uint64_t code);
  int handle_general_protection_fault(uint64_t code);
  int handle_page_fault(VM &vm, const std::shared_ptr<VCPU>& vcpu,
      uint64_t code);
  int handle_debug_trap(const std::shared_ptr<VCPU>& vcpu, uint64_t code);

  int handle_segfault(guestptr_t pfla);
}

//namespace Elkvm
}

