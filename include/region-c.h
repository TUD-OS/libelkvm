#pragma once

#include "list.h"

struct elkvm_memory_region {
       void *host_base_p;
       uint64_t guest_virtual;
       uint64_t region_size;
       int grows_downward;
       int used;
       struct elkvm_memory_region *lc;
       struct elkvm_memory_region *rc;
};

struct elkvm_memory_region *elkvm_region_create(struct kvm_vm *, uint64_t);
int elkvm_region_split(struct elkvm_memory_region *);
struct elkvm_memory_region *elkvm_region_alloc(void *, uint64_t, int);
int elkvm_region_free(struct kvm_vm *vm, struct elkvm_memory_region *region);
struct elkvm_memory_region *elkvm_region_find_free(struct elkvm_memory_region *, uint64_t);
/*
 * \brief Find the memory region a host address lies in
 */
struct elkvm_memory_region *elkvm_region_find(struct kvm_vm *vm, void *host_p);

struct elkvm_memory_region *elkvm_region_tree_traverse(struct elkvm_memory_region *region, void *host_p);

int elkvm_region_list_prepend(struct kvm_vm *,
    struct elkvm_memory_region *);

bool elkvm_is_same_region(struct kvm_vm *vm, void *host_1, void *host_2);

static inline bool
elkvm_address_in_region(struct elkvm_memory_region *region, void *host_p) {
  return (region->host_base_p <= host_p) &&
    (host_p < (region->host_base_p + region->region_size));
}
