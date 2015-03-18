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
#include <vector>

#include <elkvm/environ.h>

/* 64bit Linux puts the Stack at 47bits */
#define LINUX_64_STACK_BASE 0x800000000000
#define ELKVM_STACK_GROW    0x200000

namespace Elkvm {

  class VM;
  class Region;
  class RegionManager;

  class Stack {
    private:
      std::vector<std::shared_ptr<Region>> stack_regions;
      std::shared_ptr<RegionManager> _rm;
      std::shared_ptr<Region> kernel_stack;
      guestptr_t base;

    public:
      Stack(std::shared_ptr<RegionManager> rm);
      void init(std::shared_ptr<VCPU> v, const Environment &e,
          std::shared_ptr<RegionManager> rm);
      int pushq(guestptr_t rsp, uint64_t val);
      uint64_t popq(guestptr_t rsp);
      bool is_stack_expansion(guestptr_t pfla);
      bool grow(guestptr_t pfla);
      guestptr_t kernel_base() const { return kernel_stack->guest_address(); }
      guestptr_t user_base() const { return base; }
      int expand();
  };

//namespace Elkvm
}
