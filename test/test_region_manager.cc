#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "region.h"

namespace testing {
  class RegionManagerTest : public Test {
    protected:
      Elkvm::RegionManager rm;

      RegionManagerTest() {}
      ~RegionManagerTest() {}

      virtual void SetUp() {}
      virtual void TearDown() {}
  };

  TEST_F(RegionManagerTest, test_host_address_mapped) {
    ASSERT_FALSE(rm.host_address_mapped(reinterpret_cast<void *>(0xC0FFEE)));
    rm.add_free_region(Elkvm::Region(reinterpret_cast<void *>(0xC0F000), 0x12000));
    ASSERT_FALSE(rm.host_address_mapped(reinterpret_cast<void *>(0xC0FFEE)));
    rm.allocate_region(0x2000);
    ASSERT_TRUE(rm.host_address_mapped(reinterpret_cast<void *>(0xC0FFEE)));
  }

}
