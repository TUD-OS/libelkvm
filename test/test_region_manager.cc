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

#include <elkvm/region_manager.h>

namespace testing {
  class TheRegionManager : public Test {
    protected:
      Elkvm::RegionManager rm;

      TheRegionManager() : rm(5) {}
      ~TheRegionManager() {}

      virtual void SetUp() {}
      virtual void TearDown() {}
  };

  TEST_F(TheRegionManager, DISABLED_ReturnsThatAnUnMappedAddressIsNotMapped) {
    ASSERT_FALSE(rm.host_address_mapped(reinterpret_cast<void *>(0xC0FFEE)));
  }

  TEST_F(TheRegionManager, DISABLED_ReturnsThatAnUnMappedAddressWhichExistsIsNotMapped) {
    rm.add_free_region(std::make_shared<Elkvm::Region>(reinterpret_cast<void *>(0xC0F000), 0x12000));
    ASSERT_FALSE(rm.host_address_mapped(reinterpret_cast<void *>(0xC0FFEE)));
  }

  TEST_F(TheRegionManager, DISABLED_ReturnsThatAMappedAddressIsMapped) {
    rm.allocate_region(0x2000);
    ASSERT_TRUE(rm.host_address_mapped(reinterpret_cast<void *>(0xC0FFEE)));
  }

  TEST_F(TheRegionManager, DISABLED_ServesRequestsForSmallRegions) {
    std::shared_ptr<Elkvm::Region> r = std::make_shared<Elkvm::Region>(
        reinterpret_cast<void *>(0xC0F000), 0x12000);
    rm.add_free_region(r);

    std::shared_ptr<Elkvm::Region> r2 = rm.allocate_region(0x2000);

    ASSERT_TRUE(rm.host_address_mapped(reinterpret_cast<void *>(0xC0FFEE)));
    ASSERT_EQ(0x2000, r2->size());
    ASSERT_FALSE(r2->is_free());
  }

  TEST_F(TheRegionManager, DISABLED_FreesAnAllocatedRegionAndSetsItsGuestAddressToZero) {
    std::shared_ptr<Elkvm::Region> r = std::make_shared<Elkvm::Region>(
        reinterpret_cast<void *>(0xC0F000), 0x12000);
    rm.add_free_region(r);

    std::shared_ptr<Elkvm::Region> r2 = rm.allocate_region(0x2000);

    rm.free_region(reinterpret_cast<void *>(0xC0F000), 0x2000);
    ASSERT_EQ(0x0, r->guest_address());
  }

  TEST_F(TheRegionManager, DISABLED_ReturnsNullWhenNoFreeRegionIsAvailable) {
    std::shared_ptr<Elkvm::Region> r_res = rm.find_free_region(0x1000);
    ASSERT_EQ(r_res, nullptr);
  }

  TEST_F(TheRegionManager, DISABLED_FindsFreeRegionsWithMatchingSize) {
    std::shared_ptr<Elkvm::Region> r = std::make_shared<Elkvm::Region>(
        reinterpret_cast<void *>(0xC0F000), 0x1000);
    rm.add_free_region(r);

    auto r_res = rm.find_free_region(0x1000);

    ASSERT_EQ(r, r_res);
  }

  TEST_F(TheRegionManager, DISABLED_FindsFreeRegionsWithSmallerSize) {
    std::shared_ptr<Elkvm::Region> r2 = std::make_shared<Elkvm::Region>(
        reinterpret_cast<void *>(0xD00000), 0x12000);
    rm.add_free_region(r2);

    auto r_res = rm.find_free_region(0x1000);

    ASSERT_EQ(r2, r_res);
  }

//namespace testing
}
