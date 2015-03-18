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

#include <sys/vfs.h>

#include <elkvm/elkvm.h>
#include <elkvm/syscall.h>

long elkvm_do_statfs(Elkvm::VM * vm) {
  if(vm->get_handlers()->statfs == nullptr) {
    INFO() <<"STATFS handler not found\n";
    return -ENOSYS;
  }

  guestptr_t path_p = 0x0;
  guestptr_t buf_p = 0x0;

  vm->unpack_syscall(&path_p, &buf_p);

  char *path = nullptr;
  struct statfs *buf = nullptr;
  if(path_p != 0x0) {
    path = static_cast<char *>(vm->host_p(path_p));
  }
  if(buf_p != 0x0) {
    buf = static_cast<struct statfs *>(vm->host_p(buf_p));
  }

  int res = vm->get_handlers()->statfs(path, buf);
  if(vm->debug_mode()) {
    DBG() << "STATFS path: " << LOG_GUEST_HOST(path_p, path)
          << " [" << std::string(path) << "]"
          << " buf: " << LOG_GUEST_HOST(buf_p, buf);
    Elkvm::dbg_log_result(res);
  }

  if(res == 0) {
    return 0;
  }
  return -errno;
}

long elkvm_do_fstatfs(Elkvm::VM * vm __attribute__((unused))) {
  if(vm->get_handlers()->fstatfs == nullptr) {
    return -ENOSYS;
  }

  CURRENT_ABI::paramtype fd = 0x0;
  CURRENT_ABI::paramtype buf_p = 0x0;

  vm->unpack_syscall(&fd, &buf_p);

  struct statfs *buf = nullptr;
  if(buf_p != 0x0) {
    buf = static_cast<struct statfs *>(vm->host_p(buf_p));
  }

  auto result = vm->get_handlers()->fstatfs(fd, buf);
  if(vm->debug_mode()) {
    DBG() << "FSTATFS fd: " << std::dec << fd
          << "buf: " << LOG_GUEST_HOST(buf_p, buf);
    Elkvm::dbg_log_result(result);
  }
  return result;
}
