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

#include <iostream>
#include <iomanip>
#include <memory>

#include <inttypes.h>
#include <stdio.h>

#include <elkvm/elkvm.h>
#include <elkvm/elkvm-internal.h>
#include <elkvm/region.h>

namespace Elkvm {

  std::ostream &print(std::ostream &stream, Region const & r) {
    if(r.is_free()) {
      stream << "FREE ";
    }
    stream << std::hex
      <<"REGION[" << std::setw(36) << r.getName() << "] guest address: "
      << std::setw(19) << (void*)r.guest_address()
      << " host_p: " << r.base_address() << " size: 0x" << r.size()
      << " last guest address: 0x" << r.guest_address() + r.size() - 1
      << std::endl;
    return stream;
  }

  bool operator==(const Region &r, const void *const p) {
    return r.contains_address(p);
  }

  bool operator==(const Region &r1, const Region &r2) {
    return r1.base_address() == r2.base_address()
      && r1.guest_address() == r2.guest_address()
      && r1.size() == r2.size()
      && r1.is_free() == r2.is_free();
  }

  bool Region::contains_address(const void * const p) const {
    return (host_p <= p) && (p < (reinterpret_cast<char *>(host_p) + rsize));
  }

  bool Region::contains_address(guestptr_t guest_addr) const {
    return (addr <= guest_addr) && (guest_addr < (addr + rsize));
  }

  off64_t Region::offset_in_region(guestptr_t guest_addr) const {
    assert(contains_address(addr) && "address must be in region to calc offset");
    return guest_addr - addr;
  }

  size_t Region::space_after_address(const void * const p) const {
    assert(contains_address(p));
    return reinterpret_cast<char *>(host_p)
      + rsize - reinterpret_cast<const char * const>(p);
  }

  void *Region::last_valid_address() const {
    return reinterpret_cast<char *>(host_p) + rsize;
  }

  guestptr_t Region::last_valid_guest_address() const {
    return addr + rsize - 1;
  }

  std::shared_ptr<Region> Region::slice_begin(const size_t size,
      const std::string &purpose) {
    //assert(free);
    assert(size > 0x0);
    assert(rsize > pagesize_align(size));

    std::shared_ptr<Region> r =
      std::make_shared<Region>(host_p, pagesize_align(size), purpose);

    host_p = reinterpret_cast<char *>(host_p) + r->size();
    rsize  -= r->size();
    if(addr != 0x0) {
      addr += r->size();
    }
    assert(rsize > 0x0);
    assert(r->size() > 0x0);
    return r;
  }

  std::pair<std::shared_ptr<Region>, std::shared_ptr<Region>>
    Region::slice_center(off_t off, size_t len) {

    assert(contains_address(reinterpret_cast<char *>(host_p) + off + len));
    assert(0 < off);
    assert((unsigned)off <= rsize);

    std::shared_ptr<Region> r = std::make_shared<Region>(
        reinterpret_cast<char *>(host_p) + off + len,
        rsize - off - len);
    r->set_guest_addr(addr + off);

    rsize = off;

    std::shared_ptr<Region> free_region = std::make_shared<Region>(
          reinterpret_cast<char *>(host_p) + off, len);

    return std::pair<std::shared_ptr<Region>, std::shared_ptr<Region>>(
        r, free_region);
  }

//namespace Elkvm
}
