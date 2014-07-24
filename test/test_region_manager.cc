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

  TEST_F(TheRegionManager, ReturnsThatAnUnMappedAddressIsNotMapped) {
    ASSERT_FALSE(rm.host_address_mapped(reinterpret_cast<void *>(0xC0FFEE)));
  }

  TEST_F(TheRegionManager, ReturnsThatAnUnMappedAddressWhichExistsIsNotMapped) {
    rm.add_free_region(std::make_shared<Elkvm::Region>(reinterpret_cast<void *>(0xC0F000), 0x12000));
    ASSERT_FALSE(rm.host_address_mapped(reinterpret_cast<void *>(0xC0FFEE)));
  }

  TEST_F(TheRegionManager, ReturnsThatAMappedAddressIsMapped) {
    rm.allocate_region(0x2000);
    ASSERT_TRUE(rm.host_address_mapped(reinterpret_cast<void *>(0xC0FFEE)));
  }

  TEST_F(TheRegionManager, ServesRequestsForSmallRegions) {
    std::shared_ptr<Elkvm::Region> r = std::make_shared<Elkvm::Region>(
        reinterpret_cast<void *>(0xC0F000), 0x12000);
    rm.add_free_region(r);

    std::shared_ptr<Elkvm::Region> r2 = rm.allocate_region(0x2000);

    ASSERT_TRUE(rm.host_address_mapped(reinterpret_cast<void *>(0xC0FFEE)));
    ASSERT_EQ(0x2000, r2->size());
    ASSERT_FALSE(r2->is_free());
  }

  TEST_F(TheRegionManager, FreesAnAllocatedRegionAndSetsItsGuestAddressToZero) {
    std::shared_ptr<Elkvm::Region> r = std::make_shared<Elkvm::Region>(
        reinterpret_cast<void *>(0xC0F000), 0x12000);
    rm.add_free_region(r);

    std::shared_ptr<Elkvm::Region> r2 = rm.allocate_region(0x2000);

    rm.free_region(reinterpret_cast<void *>(0xC0F000), 0x2000);
    ASSERT_EQ(0x0, r->guest_address());
  }

  TEST_F(TheRegionManager, ReturnsNullWhenNoFreeRegionIsAvailable) {
    std::shared_ptr<Elkvm::Region> r_res = rm.find_free_region(0x1000);
    ASSERT_EQ(r_res, nullptr);
  }

  TEST_F(TheRegionManager, FindsFreeRegionsWithMatchingSize) {
    std::shared_ptr<Elkvm::Region> r = std::make_shared<Elkvm::Region>(
        reinterpret_cast<void *>(0xC0F000), 0x1000);
    rm.add_free_region(r);

    auto r_res = rm.find_free_region(0x1000);

    ASSERT_EQ(r, r_res);
  }

  TEST_F(TheRegionManager, FindsFreeRegionsWithSmallerSize) {
    std::shared_ptr<Elkvm::Region> r2 = std::make_shared<Elkvm::Region>(
        reinterpret_cast<void *>(0xD00000), 0x12000);
    rm.add_free_region(r2);

    auto r_res = rm.find_free_region(0x1000);

    ASSERT_EQ(r2, r_res);
  }

//namespace testing
}
