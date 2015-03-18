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

#include <elkvm/vcpu.h>

namespace testing {

class VCPUTest : public Test {
  protected:
    VCPUTest() : vcpu(nullptr) {}
    ~VCPUTest() {}

    virtual void SetUp() {}
    virtual void TearDown() {}

    struct kvm_vcpu vcpu;
};

TEST_F(VCPUTest, DISABLED_test_had_page_fault) {
  vcpu.sregs.cr2 = 0xc0ffee;
  int pf = kvm_vcpu_had_page_fault(&vcpu);
  ASSERT_EQ(pf, 1);
}


//namespace testing
}
