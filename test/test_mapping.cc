#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <elkvm/elkvm.h>
#include <elkvm/mapping.h>
#include <region.h>

namespace testing {

class AMapping : public Test {
  protected:
    std::shared_ptr<Elkvm::Region> r;
    Elkvm::Mapping mut;

    AMapping() :
      r(std::make_shared<Elkvm::Region>(nullptr, 0x7000, false)),
      mut(r, 0x1000, 0x2000, 0x0, 0x0, 0, 0)
  {}

};

TEST_F(AMapping, CannotBeLargerThanTheUnderlyingRegion) {
  size_t sz = mut.grow(0x8000);
  ASSERT_THAT(sz, Eq(0x7000));
}

TEST_F(AMapping, DoesNotAcceptSmallerSizeOnGrow) {
  size_t sz = mut.grow(0x1000);
  ASSERT_THAT(sz, Eq(0x2000));
}

TEST_F(AMapping, GrowsToAnExpectedSize) {
  size_t sz = mut.grow(0x4000);
  ASSERT_THAT(sz, Eq(0x4000));
  ASSERT_THAT(mut.get_pages(), Eq(4));
}


//namespace testing
}
