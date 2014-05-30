#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <elkvm/vcpu.h>

namespace testing {

class VCPUTest : public Test {
  protected:
    VCPUTest() {}
    ~VCPUTest() {}

    virtual void SetUp() {}
    virtual void TearDown() {}

    struct kvm_vcpu vcpu;
};

TEST_F(VCPUTest, test_had_page_fault) {
  vcpu.sregs.cr2 = 0xc0ffee;
  int pf = kvm_vcpu_had_page_fault(&vcpu);
  ASSERT_EQ(pf, 1);
}


//namespace testing
}
