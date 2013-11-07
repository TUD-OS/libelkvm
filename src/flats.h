#pragma once

#include <inttypes.h>

struct kvm_vm;
struct elkvm_memory_region;

struct elkvm_flat {
	struct elkvm_memory_region *region;
	uint64_t size;
};

/*
 * Load a flat binary into the guest address space
 * returns 0 on success, an errno otherwise
 */
int elkvm_load_flat(struct kvm_vm *, struct elkvm_flat *, const char *, int kernel);
