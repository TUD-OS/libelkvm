#pragma once

#include <inttypes.h>

struct kvm_vm;
struct elkvm_memory_region;

struct elkvm_flat {
	struct elkvm_memory_region *region;
	uint64_t size;
};

