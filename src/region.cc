#include <inttypes.h>
#include <stdio.h>

#include <elkvm.h>
#include "region.h"
#include "region-c.h"

struct elkvm_memory_region *elkvm_region_create(struct kvm_vm *vm, uint64_t req_size) {
  Elkvm::Region &r = Elkvm::rm.allocate_region(req_size);
	return r.c_region();
}

int elkvm_region_free(struct kvm_vm *vm, struct elkvm_memory_region *region) {
  Elkvm::rm.free_region(region->host_base_p, region->region_size);
  memset(region->host_base_p, 0, region->region_size);
  return 0;
}

struct elkvm_memory_region *
elkvm_region_tree_traverse(struct elkvm_memory_region *region, void *host_p) {
  assert(elkvm_address_in_region(region, host_p));

  if(region->lc == NULL && region->rc == NULL) {
    return region;
  }

  if(region->lc != NULL && elkvm_address_in_region(region->lc, host_p)) {
    return elkvm_region_tree_traverse(region->lc, host_p);
  }

  if(region->rc != NULL && elkvm_address_in_region(region->rc, host_p)) {
    return elkvm_region_tree_traverse(region->rc, host_p);
  }

  /* this code should not be reached */
  assert(false);
  return NULL;
}

int elkvm_region_list_prepend(struct kvm_vm *vm, struct elkvm_memory_region *region) {
  list_push_front(vm->root_region, region);
  return 0;
}

namespace Elkvm {

  bool same_region(const void *p1, const void *p2) {
    const Region &r = Elkvm::rm.find_region(p1);
    return r.contains_address(p2);
  }

  struct elkvm_memory_region *Region::c_region() const {
    struct elkvm_memory_region *r = new(struct elkvm_memory_region);
    r->host_base_p = host_p;
    r->guest_virtual = addr;
    r->region_size = size;
    r->used = !free;
    r->grows_downward = 0;
    r->rc = r->lc = NULL;
    return r;
  }

  void *Region::last_valid_address() const {
    return host_p + size;
  }

//namespace Elkvm
}
