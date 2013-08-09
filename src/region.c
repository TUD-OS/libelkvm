#include <inttypes.h>

#include <elkvm.h>
#include <region.h>

struct elkvm_memory_region *elkvm_region_create(struct kvm_vm *vm, uint64_t size) {
	return NULL;
}

int elkvm_region_split(struct kvm_vm *vm, struct elkvm_memory_region *region) {
	return -1;
}

