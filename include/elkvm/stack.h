#pragma once

#include <memory>
#include <vector>

#include <elkvm/environ.h>

/* 64bit Linux puts the Stack at 47bits */
#define LINUX_64_STACK_BASE 0x800000000000
#define ELKVM_STACK_GROW    0x200000

namespace Elkvm {

  class VM;
  class Region;
  class RegionManager;

  class Stack {
    private:
      std::vector<std::shared_ptr<Region>> stack_regions;
      std::shared_ptr<RegionManager> _rm;
      std::shared_ptr<Region> kernel_stack;
      guestptr_t base;

    public:
      Stack(std::shared_ptr<RegionManager> rm);
      void init(std::shared_ptr<VCPU> v, const Environment &e,
          std::shared_ptr<RegionManager> rm);
      int pushq(guestptr_t rsp, uint64_t val);
      uint64_t popq(guestptr_t rsp);
      bool is_stack_expansion(guestptr_t pfla);
      bool grow(guestptr_t pfla);
      guestptr_t kernel_base() const { return kernel_stack->guest_address(); }
      guestptr_t user_base() const { return base; }
      int expand();
  };

  //void dump_stack(VM &vmi, std::shared_ptr<VCPU> vcpu);

//namespace Elkvm
}
