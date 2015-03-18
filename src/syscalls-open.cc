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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <elkvm/elkvm.h>
#include <elkvm/syscall.h>

long elkvm_do_open(Elkvm::VM * vm) {
  if(vm->get_handlers()->open == nullptr) {
    ERROR() << "OPEN handler not found";
    return -ENOSYS;
  }

  CURRENT_ABI::paramtype pathname_p = 0x0;
  char *pathname = nullptr;
  CURRENT_ABI::paramtype flags = 0x0;
  CURRENT_ABI::paramtype mode = 0x0;

  vm->unpack_syscall(&pathname_p, &flags, &mode);
  assert(pathname_p != 0x0);

  pathname = static_cast<char *>(vm->host_p(pathname_p));

  long result = vm->get_handlers()->open(pathname,
      static_cast<int>(flags), static_cast<mode_t>(mode));

  if(vm->debug_mode()) {
    DBG() << "OPEN file " << LOG_GUEST_HOST(pathname_p, pathname)
          << " [" << pathname << "]"
          << " with flags 0x" << std::hex << flags
          << " mode 0x" << mode;
    Elkvm::dbg_log_result<int>(result);
  }

  return result;
}

long elkvm_do_openat(Elkvm::VM * vm) {
  if(vm->get_handlers()->openat == nullptr) {
    ERROR() << "OPENAT handler not found" << LOG_RESET << "\n";
    return -ENOSYS;
  }

  CURRENT_ABI::paramtype dirfd = 0;
  guestptr_t pathname_p = 0x0;
  CURRENT_ABI::paramtype flags = 0;

  vm->unpack_syscall(&dirfd, &pathname_p, &flags);

  char *pathname = nullptr;
  if(pathname_p != 0x0) {
    pathname = static_cast<char *>(vm->host_p(pathname_p));
  }

  int res = vm->get_handlers()->openat(static_cast<int>(dirfd),
      pathname, static_cast<int>(flags));
  if(vm->debug_mode()) {
    DBG() << "OPENAT with dirfd " << static_cast<int>(dirfd)
          << " pathname " << LOG_GUEST_HOST(pathname_p, pathname)
          << " [" << std::string(pathname) << "]"
          << " flags " << flags;
    if(dirfd == AT_FDCWD) {
      DBG() << "-> AT_FDCWD";
    }
    Elkvm::dbg_log_result(res);
  }

  if(res < 0) {
    return -errno;
  }

  return res;
}
