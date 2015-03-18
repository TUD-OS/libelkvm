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

/*
 * Basic types used by various ELKVM modules.
 */

#include <cstdint>
#include <sys/types.h>
#include <signal.h>

#include <memory>

/*
 * Guest pointer type
 */
typedef uint64_t guestptr_t;

/*
 * TODO: needs doc
 */
struct region_mapping {
  void *host_p;
  guestptr_t guest_virt;
  size_t length;
  unsigned mapped_pages;
  int prot;
  int flags;
  int fd;
  off_t offset;
};


/*
 * TODO: needs doc
 */
struct linux_dirent {
    unsigned long  d_ino;     /* Inode number */
    unsigned long  d_off;     /* Offset to next linux_dirent */
    unsigned short d_reclen;  /* Length of this linux_dirent */
    char           d_name[];  /* Filename (null-terminated) */
                              /* length is actually (d_reclen - 2 -
                                 offsetof(struct linux_dirent, d_name)) */
    /*
    char           pad;       // Zero padding byte
    char           d_type;    // File type (only since Linux
                              // 2.6.4); offset is (d_reclen - 1)
    */
};


namespace Elkvm {
class Region;


/*
 * TODO: needs doc
 */
struct elkvm_flat {
  std::shared_ptr<Elkvm::Region> region;
  uint64_t size;
};


/*
 * TODO: needs doc
 */
struct elkvm_signals {
  struct sigaction signals[_NSIG];
};
} // namespace Elkvm
