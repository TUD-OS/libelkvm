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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <elkvm/elkvm.h>
#include <elkvm/pager.h>
#include <elkvm/region_manager.h>

namespace testing {

class Pager : public Test {
  protected:
    Elkvm::PagerX86_64 pager;

    Pager() : pager(5) {}
    ~Pager() {}
};

TEST_F(Pager, DoesNotCreateAChunkWithUnalignedSize) {
  void *x = nullptr;
  int err = pager.create_mem_chunk(&x, 0x123);
  ASSERT_EQ(err, -EIO);
  ASSERT_EQ(x, nullptr);
}

TEST_F(Pager, DISABLED_CreatesAnEntryWithTheGivenAddress) {
  auto ch = pager.get_chunk(0);
  void *host_p = reinterpret_cast<void *>(0x1042 + ch->userspace_addr);
  guestptr_t guest_addr = 0xF042;

  int err = pager.map_user_page(host_p, guest_addr, 0);
  ASSERT_EQ(err, 0);

  void *created_addr = pager.get_host_p(guest_addr);
  ASSERT_EQ(host_p, created_addr);
}

TEST_F(Pager, DoesNotCreateAnUnalignedMapping) {
  guestptr_t guest_addr = 0x4ee;
  void *host_p = reinterpret_cast<void *>(0x10000 + ELKVM_SYSTEM_MEMSIZE);
  ASSERT_EQ(pager.map_user_page(host_p, guest_addr, 0), -EIO);
}


//namespace testing
}

