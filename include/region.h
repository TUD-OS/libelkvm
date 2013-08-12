#pragma once

struct elkvm_memory_region {
	void *host_base_p;
	uint64_t guest_virtual;
	uint64_t region_size;
	int grows_downward;
	int used;
	struct elkvm_memory_region *lc;
	struct elkvm_memory_region *rc;
};

struct elkvm_memory_region *elkvm_region_find(struct elkvm_memory_region *, uint64_t);
struct elkvm_memory_region *elkvm_region_create(struct kvm_vm *, uint64_t);
int elkvm_region_split(struct elkvm_memory_region *);

