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

namespace Elkvm {

enum Reg_t {
  rax, rbx, rcx, rdx,
  rsi, rdi, rsp, rbp,
  r8, r9, r10, r11,
  r12, r13, r14, r15,
  rip, rflags,
  cr0, cr2, cr3, cr4, cr8,
  efer,
  apic_base
};

enum Seg_t {
  cs, ds, es, fs, gs, ss,
  tr, ldt,
  gdt, idt
};

  //namespace Elkvm
}
