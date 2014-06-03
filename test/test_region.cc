#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "../src/region.h"

namespace testing {
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
    ASSERT_TRUE(r == reinterpret_cast<void *>(0xc10000));
    ASSERT_FALSE(r == reinterpret_cast<void *>(0xc21000));

    Elkvm::Region r2 = r;
    ASSERT_TRUE(r2 == r);

    //    XXX RM must be able to find these regions!
//    ASSERT_TRUE(Elkvm::same_region(reinterpret_cast<void *>(0xC0F000),
//                                   reinterpret_cast<void *>(0xC10000)));
//    ASSERT_FALSE(Elkvm::same_region(reinterpret_cast<void *>(0xC0F000),
//                                    reinterpret_cast<void *>(0xC21000)));
  }

  TEST_F(RegionTest, test_slicing) {
    Elkvm::Region r2 = r.slice_begin(0x1000);
    ASSERT_FALSE(r.contains_address(reinterpret_cast<void *>(0xC0F000)));
    ASSERT_TRUE(r.contains_address(reinterpret_cast<void *>(0xC10000)));
    ASSERT_TRUE(r2.contains_address(reinterpret_cast<void *>(0xC0F000)));
    ASSERT_TRUE(r2.contains_address(reinterpret_cast<void *>(0xC0FFFF)));
    ASSERT_FALSE(r2.contains_address(reinterpret_cast<void *>(0xC10000)));
    ASSERT_TRUE(r.contains_address(reinterpret_cast<void *>(0xc20fff)));
  }

}
