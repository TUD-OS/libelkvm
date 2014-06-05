#pragma once

#include <stdbool.h>

#include "elkvm.h"
#include "region-c.h"

#ifdef __cplusplus
extern "C" {
#endif

int elkvm_heap_initialize(struct kvm_vm *, struct elkvm_memory_region *, uint64_t);
int elkvm_heap_grow(struct kvm_vm *, uint64_t size);

int elkvm_brk(struct kvm_vm *, guestptr_t newbrk);
int elkvm_brk_nogrow(struct kvm_vm *, guestptr_t newbrk);
int elkvm_brk_shrink(struct kvm_vm *, guestptr_t newbrk);
int elkvm_brk_grow(struct kvm_vm *, guestptr_t newbrk);

int elkvm_brk_map(struct kvm_vm *, guestptr_t newbrk, uint64_t off);

bool elkvm_within_current_heap_region(struct kvm_vm *vm, guestptr_t guest_addr);
guestptr_t elkvm_last_heap_address(struct kvm_vm *vm);

#ifdef __cplusplus
}
#endif
