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
