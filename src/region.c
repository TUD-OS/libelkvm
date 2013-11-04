#include <inttypes.h>
#include <stdio.h>

#include <elkvm.h>
#include <region.h>

struct elkvm_memory_region *elkvm_region_create(struct kvm_vm *vm, uint64_t size) {
	struct elkvm_memory_region_list *current_root = vm->root_region;
  struct elkvm_memory_region *current = current_root->data;

  do {
    current = current_root->data;
    assert(current != NULL);
    current = elkvm_region_find(current, size);
  } while((current == NULL) && !((current_root = current_root->next) == NULL));

  if(current == NULL) {
    /* TODO get a new memory chunk and add that to the list of root regions */
    void *chunk_p;
    uint64_t grow_size = size > ELKVM_SYSTEM_MEMGROW ? size : ELKVM_SYSTEM_MEMGROW;
    int err = kvm_pager_create_mem_chunk(&vm->pager, &chunk_p, grow_size);
    if(err) {
      return NULL;
    }
    current = elkvm_region_alloc(chunk_p, grow_size, 0);
    if(current == NULL) {
      return NULL;
    }
    current_root = elkvm_region_list_prepend(vm, current);
    if(current_root == NULL) {
      return NULL;
    }

  }

	current->used = 1;

	return current;
}

int elkvm_region_split(struct elkvm_memory_region *region) {
	if(region->used) {
		return -1;
	}
  if(region->region_size < 0x1000) {
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

struct elkvm_memory_region *
	elkvm_region_find(struct elkvm_memory_region *region, uint64_t size) {
		if(size > region->region_size) {
			return NULL;
		}

		uint64_t smaller_size = region->region_size / 2;
		if((smaller_size < 0x1000) ||
        ((smaller_size < size) && (size <= region->region_size))) {
			if(region->used == 0) {
				return region;
			} else {
				return NULL;
			}
		}

		if(region->lc != NULL) {
			struct elkvm_memory_region *child = elkvm_region_find(region->lc, size);
			if(child) {
				return child;
			}

			assert(region->rc != NULL);
			child = elkvm_region_find(region->rc, size);
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
			return elkvm_region_find(region->lc, size);
		}
}

struct elkvm_memory_region_list *elkvm_region_list_prepend(struct kvm_vm *vm,
    struct elkvm_memory_region *region) {
  struct elkvm_memory_region_list *l =
    malloc(sizeof(struct elkvm_memory_region_list));
  if(l == NULL) {
    return l;
  }
  l->next = vm->root_region;
  l->data = region;
  vm->root_region = l;
  return l;
}

