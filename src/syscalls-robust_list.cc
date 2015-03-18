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

#include <linux/futex.h>
#include <sys/types.h>

long elkvm_do_set_robust_list(Elkvm::VM *vm __attribute__((unused))) {
  if(vm->get_handlers()->set_robust_list == nullptr) {
    return -ENOSYS;
  }

  struct robust_list_head *head = nullptr;
  size_t len = 0x0;
  CURRENT_ABI::paramtype head_p = 0x0;

  vm->unpack_syscall(&head_p, &len);
  assert(head_p != 0x0);

  head = static_cast<struct robust_list_head *>(vm->host_p(head_p));
  long result = vm->get_handlers()->set_robust_list(head, len);
  if(vm->debug_mode()) {
    DBG() << "SET ROBUST LIST: head: " << LOG_GUEST_HOST(head_p, head)
          << " len: " << len;
    Elkvm::dbg_log_result<int>(result);
  }
  return result;
}

