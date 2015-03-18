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

#include <sys/time.h>
#include <sys/resource.h>

long elkvm_do_getrlimit(Elkvm::VM *vm) {
  CURRENT_ABI::paramtype resource = 0x0;
  CURRENT_ABI::paramtype rlim_p = 0x0;
  struct rlimit *rlim = NULL;

  vm->unpack_syscall(&resource, &rlim_p);

  assert(rlim_p != 0x0);
  rlim = static_cast<struct rlimit *>(vm->host_p(rlim_p));

  memcpy(rlim, vm->get_rlimit(resource), sizeof(struct rlimit));
  if(vm->debug_mode()) {
    DBG() << "GETRLIMIT with resource: " << std::dec << resource
          << " rlim: " << LOG_GUEST_HOST(rlim_p, rlim);
  }

  return 0;
}

long elkvm_do_setrlimit(Elkvm::VM * vm) {
  if(vm->get_handlers()->setrlimit == nullptr) {
    return -ENOSYS;
  }

  CURRENT_ABI::paramtype resource = 0x0;
  CURRENT_ABI::paramtype rlim_p = 0x0;
  const struct rlimit *rlim = nullptr;

  vm->unpack_syscall(&resource, &rlim_p);
  assert(rlim_p != 0x0);

  rlim = static_cast<const struct rlimit *>(vm->host_p(rlim_p));

  int err = vm->get_handlers()->setrlimit(resource, rlim);
  if(err == 0) {
    vm->set_rlimit(resource, rlim);
  }

  if(vm->debug_mode()) {
    DBG() << "GETRLIMIT with resource: " << std::dec << resource
          << " rlim: " << LOG_GUEST_HOST(rlim_p, rlim);
    Elkvm::dbg_log_result<int>(err);
  }
  return err;
}
