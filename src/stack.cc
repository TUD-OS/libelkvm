#include <assert.h>
#include <errno.h>

#include <elkvm.h>
#include <environ.h>
#include <pager.h>
#include <stack.h>
#include <stack-c.h>
#include <vcpu.h>
#include "debug.h"

namespace Elkvm {
  extern RegionManager rm;
  Stack stack;

  void Stack::init(struct kvm_vcpu *v, struct kvm_pager *p, const Environment &env) {
    vcpu = v;
    pager = p;

    int err = kvm_vcpu_get_regs(vcpu);
    assert(err == 0 && "error getting vcpu");

    /* get memory for the stack, this is expanded as needed */
    err = expand();
    assert(err == 0 && "stack creation failed");

    /* get a frame for the kernel (interrupt) stack */
    /* this is only ONE page large */
    kernel_stack = rm.allocate_region(ELKVM_PAGESIZE);

    /* create a mapping for the kernel (interrupt) stack */
    guestptr_t kstack_addr = elkvm_pager_map_kernel_page(pager,
        kernel_stack->base_address(), 1, 0);
    assert(kstack_addr != 0x0 && "could not allocate memory for kernel stack");

    kernel_stack->set_guest_addr(kstack_addr);

    /* as the stack grows downward we can initialize its address at the base address
     * of the env region */
    vcpu->regs.rsp = env.get_guest_address();
    err = elkvm_pager_create_mapping(pager,
        env.get_base_address(),
        vcpu->regs.rsp, PT_OPT_WRITE);
    assert(err == 0 && "could not map stack address");

    base = env.get_guest_address();

    err = kvm_vcpu_set_regs(vcpu);
    assert(err == 0 && "could not set registers");
  }

  int Stack::pushq(uint64_t val) {
    vcpu->regs.rsp -= 0x8;

    assert(vcpu->regs.rsp != 0x0);
    uint64_t *host_p = reinterpret_cast<uint64_t *>(
        elkvm_pager_get_host_p(pager, vcpu->regs.rsp));
    if(host_p == nullptr) {
      /* current stack is full, we need to expand the stack */
      int err = expand();
      if(err) {
        return err;
      }
      host_p = reinterpret_cast<uint64_t *>(
          elkvm_pager_get_host_p(pager, vcpu->regs.rsp));
      assert(host_p != NULL);
    }
    *host_p = val;
    return 0;
  }

  uint64_t Stack::popq() {
    assert(vcpu->regs.rsp != 0x0);
    uint64_t *host_p = reinterpret_cast<uint64_t *>(
        elkvm_pager_get_host_p(pager, vcpu->regs.rsp));
    assert(host_p != NULL);

    vcpu->regs.rsp += 0x8;

    return *host_p;
  }

  int Stack::expand() {
    base -= ELKVM_STACK_GROW;

    std::shared_ptr<Region> region = rm.allocate_region(ELKVM_STACK_GROW);
    if(region == nullptr) {
      return -ENOMEM;
    }

    int err = elkvm_pager_map_region(pager, region->base_address(), base,
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

//namespace Elkvm
}

#ifdef __cplusplus
extern "C" {
#endif

void elkvm_dump_stack(struct kvm_vm *vm, struct kvm_vcpu *vcpu) {
  assert(vcpu->regs.rsp != 0x0);
  elkvm_dump_memory(vm, vcpu->regs.rsp);
}

int elkvm_pushq(struct kvm_vm *vm __attribute__((unused)),
    struct kvm_vcpu *vcpu __attribute__((unused)),
    uint64_t val) {
  return Elkvm::stack.pushq(val);
}

uint64_t elkvm_popq(struct kvm_vm *vm __attribute__((unused)),
    struct kvm_vcpu *vcpu __attribute__((unused))) {
  return Elkvm::stack.popq();
}

bool elkvm_check_stack_grow(guestptr_t pfla) {
  return Elkvm::stack.grow(pfla);
}

guestptr_t elkvm_get_kernel_stack_base() {
  /* as stack grows downward we return it's virtual address
   * at the page afterwards */
  return Elkvm::stack.kernel_base() + ELKVM_PAGESIZE;
}

#ifdef __cplusplus
}
#endif
