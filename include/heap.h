#pragma once

#include <stdbool.h>

#include "elkvm.h"
#include "region.h"

int elkvm_heap_initialize(struct kvm_vm *, struct elkvm_memory_region *, uint64_t);
int elkvm_heap_grow(struct kvm_vm *, uint64_t size);

int elkvm_brk(struct kvm_vm *, uint64_t);
int elkvm_brk_nogrow(struct kvm_vm *, uint64_t);
int elkvm_brk_grow(struct kvm_vm *);

static inline bool elkvm_within_current_heap_region(struct kvm_vm *vm, uint64_t guest_addr) {
  return guest_addr < (vm->heap->data->guest_virtual + vm->heap->data->region_size);
}
