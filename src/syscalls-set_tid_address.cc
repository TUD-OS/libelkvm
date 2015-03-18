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

#include <elkvm/elkvm.h>
#include <elkvm/syscall.h>

long elkvm_do_set_tid_address(Elkvm::VM * vm) {
  if(vm->get_handlers()->set_tid_address == nullptr) {
    return -ENOSYS;
  }

  int *tidptr = nullptr;
  CURRENT_ABI::paramtype tidptr_p = 0x0;
  vm->unpack_syscall(&tidptr_p);
  assert(tidptr_p != 0x0);

  tidptr = static_cast<int *>(vm->host_p(tidptr_p));
  assert(tidptr != nullptr);
  long result = vm->get_handlers()->set_tid_address(tidptr);
  if(vm->debug_mode()) {
    DBG() << "SET TID ADDRESS tidptr at: " << LOG_GUEST_HOST(tidptr_p, tidptr);
    Elkvm::dbg_log_result(result);
  }

  return result;
}

