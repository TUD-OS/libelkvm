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

#include <elkvm/region.h>

namespace testing {
  class MockRegionManager {
    MOCK_METHOD1(use_region, void(std::shared_ptr<Elkvm::Region> r));
  };

  class RegionTest : public Test {
    protected:
      Elkvm::Region r;

      RegionTest() :
        r(reinterpret_cast<void *>(0xC0F000), 0x12000) {}
      ~RegionTest() {}

      virtual void SetUp() {}
      virtual void TearDown() {}
  };

  TEST_F(RegionTest, test_contains_address) {
    ASSERT_FALSE(r.contains_address(reinterpret_cast<void *>(0xc0efff)));
    ASSERT_TRUE(r.contains_address(reinterpret_cast<void *>(0xc0f000)));
    ASSERT_TRUE(r.contains_address(reinterpret_cast<void *>(0xc10000)));
    ASSERT_TRUE(r.contains_address(reinterpret_cast<void *>(0xc20fff)));
    ASSERT_FALSE(r.contains_address(reinterpret_cast<void *>(0xc21000)));
  }

  TEST_F(RegionTest, test_equality) {

    Elkvm::Region r2 = r;
    ASSERT_TRUE(r2 == r);

    //    XXX RM must be able to find these regions!
//    ASSERT_TRUE(Elkvm::same_region(reinterpret_cast<void *>(0xC0F000),
//                                   reinterpret_cast<void *>(0xC10000)));
//    ASSERT_FALSE(Elkvm::same_region(reinterpret_cast<void *>(0xC0F000),
//                                    reinterpret_cast<void *>(0xC21000)));
  }

  TEST_F(RegionTest, test_slice_begin) {
    std::shared_ptr<Elkvm::Region> r2 = r.slice_begin(0x1000);
    ASSERT_FALSE(r.contains_address(reinterpret_cast<void *>(0xC0F000)));
    ASSERT_TRUE(r.contains_address(reinterpret_cast<void *>(0xC10000)));
    ASSERT_TRUE(r2->contains_address(reinterpret_cast<void *>(0xC0F000)));
    ASSERT_TRUE(r2->contains_address(reinterpret_cast<void *>(0xC0FFFF)));
    ASSERT_FALSE(r2->contains_address(reinterpret_cast<void *>(0xC10000)));
    ASSERT_TRUE(r.contains_address(reinterpret_cast<void *>(0xc20fff)));
  }

  TEST_F(RegionTest, test_slice_center) {
    r.set_used();
    r.slice_center(0x1000, 0x1000);
    ASSERT_EQ(r.base_address(), reinterpret_cast<void *>(0xC0F000));
    ASSERT_EQ(r.size(), 0x1000);
    ASSERT_FALSE(r.contains_address(reinterpret_cast<void *>(0xC10000)));

    //    TODO check if 2nd region is correct
//    std::shared_ptr<Elkvm::Region> r2 = Elkvm::rm.find_region(0xC11000);
//    ASSERT_EQ(r2->base_address(), 0xC11000);
//    ASSERT_EQ(r2->size(), 0x10000);
  }

}
