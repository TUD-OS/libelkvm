#include <assert.h>
#include <errno.h>

#include <elkvm.h>
#include <elkvm-internal.h>
#include <environ.h>
#include <pager.h>
#include <stack.h>
#include <vcpu.h>
#include "debug.h"

namespace Elkvm {
  Stack stack;
  extern std::unique_ptr<VMInternals> vmi;

  void Stack::init(struct kvm_vcpu *v, const Environment &env) {
    vcpu = v;

    int err = kvm_vcpu_get_regs(vcpu);
    assert(err == 0 && "error getting vcpu");

    /* as the stack grows downward we can initialize its address at the base address
     * of the env region */
    base = vcpu->regs.rsp = env.get_guest_address();

    /* get memory for the stack, this is expanded as needed */
    err = expand();
    assert(err == 0 && "stack creation failed");

    /* get a frame for the kernel (interrupt) stack */
    /* this is only ONE page large */
    kernel_stack = vmi->get_region_manager().allocate_region(ELKVM_PAGESIZE);

    /* create a mapping for the kernel (interrupt) stack */
    guestptr_t kstack_addr = vmi->get_region_manager().get_pager().map_kernel_page(kernel_stack->base_address(),
       PT_OPT_WRITE);
    assert(kstack_addr != 0x0 && "could not allocate memory for kernel stack");

    kernel_stack->set_guest_addr(kstack_addr);

    err = kvm_vcpu_set_regs(vcpu);
    assert(err == 0 && "could not set registers");
  }

  int Stack::pushq(uint64_t val) {
    vcpu->regs.rsp -= 0x8;

    assert(vcpu->regs.rsp != 0x0);
    uint64_t *host_p = reinterpret_cast<uint64_t *>(
        vmi->get_region_manager().get_pager().get_host_p(vcpu->regs.rsp));
    if(host_p == nullptr) {
      /* current stack is full, we need to expand the stack */
      int err = expand();
      if(err) {
        return err;
      }
      host_p = reinterpret_cast<uint64_t *>(vmi->get_region_manager().get_pager().get_host_p(vcpu->regs.rsp));
      assert(host_p != NULL);
    }
    *host_p = val;
    return 0;
  }

  uint64_t Stack::popq() {
    assert(vcpu->regs.rsp != 0x0);
    uint64_t *host_p = reinterpret_cast<uint64_t *>(
        vmi->get_region_manager().get_pager().get_host_p(vcpu->regs.rsp));
    assert(host_p != NULL);

    vcpu->regs.rsp += 0x8;

    return *host_p;
  }

  int Stack::expand() {
    base -= ELKVM_STACK_GROW;

    std::shared_ptr<Region> region = vmi->get_region_manager().allocate_region(ELKVM_STACK_GROW);
    if(region == nullptr) {
      return -ENOMEM;
    }

    int err = vmi->get_region_manager().get_pager().map_region(region->base_address(), base,
        ELKVM_STACK_GROW / ELKVM_PAGESIZE, PT_OPT_WRITE);
    if(err) {
      return err;
    }

    region->set_guest_addr(base);
    stack_regions.push_back(region);

    return 0;
  }

  bool Stack::is_stack_expansion(guestptr_t pfla) {
    guestptr_t stack_top = page_begin(stack_regions.back()->guest_address());
    if(pfla > stack_top) {
      return false;
    }

    guestptr_t aligned_pfla = page_begin(pfla);
    uint64_t pages = pages_from_size(stack_top - aligned_pfla);

    /* TODO right now this is an arbitrary number... */
    return pages < 200;
  }

  bool Stack::grow(guestptr_t pfla) {
    if(is_stack_expansion(pfla)) {
      int err = expand();
      assert(err == 0);
      return true;
    }

    return false;
  }

  guestptr_t Stack::kernel_base() {
    return kernel_stack->guest_address();
  }

  void dump_stack(VMInternals &vmi, struct kvm_vcpu *vcpu) {
    assert(vcpu->regs.rsp != 0x0);
    //elkvm_dump_memory(vm, vcpu->regs.rsp);
  }

//namespace Elkvm
}
