#include "vcpu.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 64bit Linux puts the Stack at 47bits */
#define LINUX_64_STACK_BASE 0x800000000000

/*
 * Push a value onto the Stack of the VM
 */
int elkvm_pushq(struct kvm_vm *, struct kvm_vcpu *, uint64_t);

/*
 * Pop a value from the VM's Stack
 */
uint64_t elkvm_popq(struct kvm_vm *, struct kvm_vcpu *);

uint32_t elkvm_popd(struct kvm_vm *, struct kvm_vcpu *);

/*
 * \brief Expand the Stack by one Frame
 */
int expand_stack(struct kvm_vm *, struct kvm_vcpu *);

/*
 * Dump the stack to stdout
 */
void elkvm_dump_stack(struct kvm_vm *, struct kvm_vcpu *vcpu);

static int is_stack_expansion(struct kvm_vm *vm, struct kvm_vcpu *vcpu,
    uint64_t pfla) {
  uint64_t stack_top = page_begin(vm->current_user_stack->guest_virtual);
  if(pfla > stack_top) {
    return 0;
  }

  uint64_t aligned_pfla = page_begin(pfla);
  uint64_t pages = pages_from_size(stack_top - aligned_pfla);

  /* TODO right now this is an arbitrary number... */
  return pages < 0x20;
}

#ifdef __cplusplus
}
#endif
