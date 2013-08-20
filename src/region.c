#include <inttypes.h>
#include <stdio.h>

#include <elkvm.h>
#include <region.h>

struct elkvm_memory_region *elkvm_region_create(struct kvm_vm *vm, uint64_t size) {
	struct elkvm_memory_region *current = &vm->root_region;
	current = elkvm_region_find(current, size);
	if(current == NULL) {
		return NULL;
	}

	current->used = 1;

	return current;
}

int elkvm_region_split(struct elkvm_memory_region *region) {
	if(region->used) {
		return -1;
	}
	region->used = 1;

	region->lc = malloc(sizeof(struct elkvm_memory_region));
	region->lc->host_base_p = region->host_base_p;
	region->lc->guest_virtual = 0x0;
	region->lc->region_size = region->region_size / 2;
	region->lc->grows_downward = 0;
	region->lc->used = 0;
	region->lc->lc = region->lc->rc = NULL;

	region->rc = malloc(sizeof(struct elkvm_memory_region));
	region->rc->host_base_p = region->host_base_p + region->lc->region_size;
	region->rc->guest_virtual = 0x0;
	region->rc->region_size = region->region_size / 2;
	region->rc->grows_downward = 0;
	region->rc->used = 0;
	region->rc->lc = region->rc->rc = NULL;

	return 0;
}

struct elkvm_memory_region *
	elkvm_region_find(struct elkvm_memory_region *region, uint64_t size) {
		if(size > region->region_size) {
			return NULL;
		}

		uint64_t smaller_size = region->region_size / 2;
		if((smaller_size < size) && (size <= region->region_size)) {
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
