#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <elkvm/elkvm.h>
#include <elkvm/pager.h>

namespace testing {

class PagerTest : public Test {
  protected:
    PagerTest() {}
    ~PagerTest() {}

    virtual void SetUp() {
      elkvm_region_setup(&vm);
      vm.pager.vm = &vm;
      vm.pager.host_pml4_p = reinterpret_cast<void *>(
          vm.pager.system_chunk.userspace_addr + 0x1000);
      vm.pager.host_next_free_tbl_p = vm.pager.host_pml4_p + 0x1000;
    }
    virtual void TearDown() {
      free(vm.pager.host_pml4_p - 0x1000);
    }

    struct kvm_vm vm;
};

TEST_F(PagerTest, test_create_entry) {
  void *host_p = reinterpret_cast<void *>(vm.pager.system_chunk.userspace_addr
      + 0xFEE);
  guestptr_t guest_addr = reinterpret_cast<guestptr_t>(host_p) & 0xFFF;

  int err = kvm_pager_create_mapping(&vm.pager, host_p, guest_addr, 0);
  ASSERT_EQ(err, 0);

  void *host_created = kvm_pager_get_host_p(&vm.pager, guest_addr);
  ASSERT_EQ(host_p, host_created);
}

TEST_F(PagerTest, test_create_invalid_entry) {
  guestptr_t guest_addr = 0x4ee;
  void *host_p = reinterpret_cast<void *>(vm.pager.system_chunk.userspace_addr);

  int err = kvm_pager_create_mapping(&vm.pager, host_p, guest_addr, 0);
  ASSERT_EQ(err, -EIO);
}


//namespace testing
}

