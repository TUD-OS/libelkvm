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
