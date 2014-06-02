#include <inttypes.h>
#include <stdio.h>

#include <elkvm.h>
#include <region.h>

struct elkvm_memory_region *elkvm_region_create(struct kvm_vm *vm, uint64_t req_size) {

  uint64_t size = req_size;
  if(req_size < ELKVM_PAGESIZE) {
    size = ELKVM_PAGESIZE;
  }

  struct elkvm_memory_region *r = NULL;
  list_each(vm->root_region, current) {
    r = elkvm_region_find_free(current, size);
    if(r != NULL) {
      break;
    }
  }

  if(r == NULL) {
    /* get a new memory chunk and add that to the list of root regions */
    void *chunk_p;
    uint64_t grow_size = size > ELKVM_SYSTEM_MEMGROW ? pagesize_align(size) : ELKVM_SYSTEM_MEMGROW;
    int err = elkvm_pager_create_mem_chunk(&vm->pager, &chunk_p, grow_size);
    if(err) {
      return NULL;
    }
    r = elkvm_region_alloc(chunk_p, grow_size, 0);
    if(r == NULL) {
      return NULL;
    }
    elkvm_region_list_prepend(vm, r);
    r  = elkvm_region_find_free(r, size);

  }

	r->used = 1;

	return r;
}

int elkvm_region_split(struct elkvm_memory_region *region) {
	if(region->used) {
		return -1;
	}
  if(region->region_size < ELKVM_PAGESIZE) {
    return -1;
  }
	region->used = 1;

  region->lc = elkvm_region_alloc(region->host_base_p, region->region_size / 2, 0);
  region->rc = elkvm_region_alloc(region->host_base_p + region->lc->region_size,
      region->region_size / 2, 0);

	return 0;
}

struct elkvm_memory_region *elkvm_region_alloc(void *host_base_p, uint64_t size,
    int down) {
  struct elkvm_memory_region *region;
	region = malloc(sizeof(struct elkvm_memory_region));
  if(region == NULL) {
    return NULL;
  }
	region->host_base_p = host_base_p;
	region->guest_virtual = 0x0;
	region->region_size = size;
	region->grows_downward = down;
	region->used = 0;
	region->lc = region->rc = NULL;
  return region;
}

void elkvm_region_free(struct elkvm_memory_region *region) {
  assert(region->lc == NULL);
  assert(region->rc == NULL);

  region->guest_virtual = 0x0;
  region->used = 0;
  region->grows_downward = 0;
  memset(region->host_base_p, 0, region->region_size);
}

struct elkvm_memory_region *
	elkvm_region_find_free(struct elkvm_memory_region *region, uint64_t size) {
    assert(size >= ELKVM_PAGESIZE);

		if(size > region->region_size) {
			return NULL;
		}

		uint64_t smaller_size = region->region_size / 2;
		if((smaller_size <= ELKVM_PAGESIZE) ||
        ((smaller_size < size) && (size <= region->region_size))) {
			if(region->used == 0) {
				return region;
			} else {
				return NULL;
			}
		}

		if(region->lc != NULL) {
			struct elkvm_memory_region *child = elkvm_region_find_free(region->lc, size);
			if(child) {
				return child;
			}

			assert(region->rc != NULL);
			child = elkvm_region_find_free(region->rc, size);
			return child;
		} else {
			assert(region->rc == NULL);
			if(region->used) {
				return NULL;
			}

			int err = elkvm_region_split(region);
			if(err != 0) {
				return NULL;
			}
			return elkvm_region_find_free(region->lc, size);
		}
}

struct elkvm_memory_region *elkvm_region_find(struct kvm_vm *vm, void *host_p) {
  list_each(vm->root_region, region) {
    if(elkvm_address_in_region(region, host_p)) {
      return elkvm_region_tree_traverse(region, host_p);
    }
  }

  return NULL;
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

bool elkvm_is_same_region(struct kvm_vm *vm, void *host_1, void *host_2) {
  struct elkvm_memory_region *region;
  region = elkvm_region_find(vm, host_1);
  if(region == NULL) {
    return false;
  }

  return elkvm_address_in_region(region, host_2);
}


int elkvm_region_list_prepend(struct kvm_vm *vm, struct elkvm_memory_region *region) {
  list_push_front(vm->root_region, region);
  return 0;
}

bool elkvm_address_in_region(struct elkvm_memory_region *region, void *host_p) {
  return (region->host_base_p <= host_p) &&
    ((char *)host_p < ((char *)region->host_base_p + region->region_size));
}
