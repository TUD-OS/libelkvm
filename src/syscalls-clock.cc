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

#include <time.h>

long elkvm_do_clock_gettime(Elkvm::VM * vm) {
  if(vm->get_handlers()->clock_gettime == NULL) {
    ERROR() << "CLOCK GETTIME handler not found" << LOG_RESET << "\n";
    return -ENOSYS;
  }

  CURRENT_ABI::paramtype clk_id = 0x0;
  CURRENT_ABI::paramtype tp_p = 0x0;
  struct timespec *tp = nullptr;

  vm->unpack_syscall(&clk_id, &tp_p);
  assert(tp_p != 0x0);

  tp = static_cast<struct timespec *>(vm->host_p(tp_p));
  assert(tp != nullptr);

  long result = vm->get_handlers()->clock_gettime(clk_id, tp);
  if(vm->debug_mode()) {
    DBG() << "CLOCK GETTIME with clk_id: " << clk_id
          << " tp: " << LOG_GUEST_HOST(tp_p, tp);
    Elkvm::dbg_log_result<int>(result);
  }
  return result;
}

long elkvm_do_clock_getres(Elkvm::VM * vm) {
  if(vm->get_handlers()->clock_getres == nullptr) {
    return -ENOSYS;
  }

  CURRENT_ABI::paramtype clk_id = 0x0;
  CURRENT_ABI::paramtype res_p = 0x0;
  struct timespec *res = nullptr;

  vm->unpack_syscall(&clk_id, &res_p);
  assert(res_p != 0x0);

  res = static_cast<struct timespec *>(vm->host_p(res_p));
  assert(res != nullptr);

  auto result = vm->get_handlers()->clock_getres(clk_id, res);
  if(vm->debug_mode()) {
    DBG() << "CLOCK GETRES with clk_id: " << std::dec << clk_id
          << " res: " << LOG_GUEST_HOST(res_p, res);
    Elkvm::dbg_log_result(result);
  }
  return result;
}
