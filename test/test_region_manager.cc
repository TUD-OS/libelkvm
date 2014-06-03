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

  TEST_F(RegionManagerTest, test_free_region) {
    Elkvm::Region r(reinterpret_cast<void *>(0xC0F000), 0x12000);
    rm.add_free_region(r);
    Elkvm::Region r2 = rm.allocate_region(0x2000);
    ASSERT_TRUE(rm.host_address_mapped(reinterpret_cast<void *>(0xC0FFEE)));
    ASSERT_EQ(0x2000, r2.size());
    ASSERT_FALSE(r2.is_free());
    rm.free_region(reinterpret_cast<void *>(0xC0F000), 0x2000);
    ASSERT_EQ(0x0, r.guest_address());
  }


  TEST_F(RegionManagerTest, test_find_free_region) {
    Elkvm::Region r_res = rm.find_free_region(0x1000);
    ASSERT_EQ(r_res.base_address(), nullptr);

    Elkvm::Region r(reinterpret_cast<void *>(0xC0F000), 0x1000);
    rm.add_free_region(r);
    r_res = rm.find_free_region(0x1000);
    ASSERT_EQ(r, r_res);
    rm.add_free_region(r);

    Elkvm::Region r2(reinterpret_cast<void *>(0xD00000), 0x12000);
    rm.add_free_region(r2);
    r_res = rm.find_free_region(0x1000);
    ASSERT_EQ(r, r_res);
    rm.add_free_region(r);

    r_res = rm.find_free_region(0x2000);
    ASSERT_EQ(r2, r_res);
  }

//namespace testing
}
