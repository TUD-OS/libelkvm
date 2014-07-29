#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <elfloader.h>
#include <pager.h>

namespace testing {

  class AnElfBinary : public Test {

  };

  TEST(AnElfBinary, SetsWritePagerOption) {
    ptopt_t opts = Elkvm::get_pager_opts_from_phdr_flags(PF_W);
    ASSERT_THAT(opts, Eq(PT_OPT_WRITE));
  }

  TEST(AnElfBinary, SetsExecutePagerOption) {
    ptopt_t opts = Elkvm::get_pager_opts_from_phdr_flags(PF_X);
    ASSERT_THAT(opts, Eq(PT_OPT_EXEC));
  }

//namespace testing
}
