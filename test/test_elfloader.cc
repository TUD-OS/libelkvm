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
