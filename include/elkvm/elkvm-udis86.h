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

#include <elkvm/config.h>

#ifdef HAVE_LIBUDIS86
#include <udis86.h>
#endif

#include <elkvm/types.h>

namespace Elkvm {

class UDis {
  private:
      const unsigned bits = 64;
      const size_t disassembly_size = 40;

    #ifdef HAVE_LIBUDIS86
      ud_t ud_obj;
    #endif

  public:
      UDis(const uint8_t *ptr);
      int disassemble();
      std::string next_insn();
};

//namespace Elkvm
}
