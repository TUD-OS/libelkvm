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

long elkvm_do_sigaction(Elkvm::VM * vm) {
  if(vm->get_handlers()->sigaction == nullptr) {
    ERROR() << "SIGACTION handler not found" << LOG_RESET << "\n";
    return -ENOSYS;
  }

  CURRENT_ABI::paramtype signum;
  CURRENT_ABI::paramtype act_p;
  CURRENT_ABI::paramtype oldact_p;

  vm->unpack_syscall(&signum, &act_p, &oldact_p);

  struct sigaction *act = nullptr;
  struct sigaction *oldact = nullptr;
  if(act_p != 0x0) {
    act = static_cast<struct sigaction *>(vm->host_p(act_p));
  }
  if(oldact_p != 0x0) {
    oldact = static_cast<struct sigaction *>(vm->host_p(oldact_p));
  }

  int err = 0;
  if(vm->get_handlers()->sigaction(static_cast<int>(signum), act, oldact)) {
    err = vm->signal_register(static_cast<int>(signum), act, oldact);
  }

  if(vm->debug_mode()) {
    DBG() << "SIGACTION with signum " << signum
          << " act " << LOG_GUEST_HOST(act_p, act)
          << " oldact " << LOG_GUEST_HOST(oldact_p, oldact);
    Elkvm::dbg_log_result<int>(err);
  }

  return err;
}

long elkvm_do_sigprocmask(Elkvm::VM * vm) {
  if(vm->get_handlers()->sigprocmask == nullptr) {
    ERROR() << "SIGPROCMASK handler not found" << LOG_RESET << "\n";
    return -ENOSYS;
  }

  CURRENT_ABI::paramtype how;
  CURRENT_ABI::paramtype set_p;
  CURRENT_ABI::paramtype oldset_p;

  vm->unpack_syscall(&how, &set_p, &oldset_p);

  sigset_t *set = nullptr;
  sigset_t *oldset = nullptr;
  if(set_p != 0x0) {
    set = static_cast<sigset_t *>(vm->host_p(set_p));
  }
  if(oldset_p != 0x0) {
    oldset = static_cast<sigset_t *>(vm->host_p(oldset_p));
  }

  long result = vm->get_handlers()->sigprocmask(how, set, oldset);
  if(vm->debug_mode()) {
    DBG() << "RT SIGPROCMASK with how: " << how << " (" << (void*)&how << ") "
          << "set: " << (void*)set_p << " (" << (void*)set << ") "
          << "oldset: " << (void*)oldset_p << " (" << (void*)oldset;
    Elkvm::dbg_log_result<int>(result);
  }
  return result;
}
