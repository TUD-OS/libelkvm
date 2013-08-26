#include "vcpu.h"

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
void dump_stack(struct kvm_vm *);

