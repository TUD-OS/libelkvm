#pragma once

struct elkvm_flat {
	uint64_t offset;
	uint64_t size;
};

/*
 * Load a flat binary into the guest address space
 * returns 0 on success, an errno otherwise
 */
int elkvm_load_flat(struct kvm_vm *, struct elkvm_flat *, const char *);
