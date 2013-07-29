#pragma once

struct elkvm_memory_region {
	void *host_base_p;
	uint64_t guest_virtual;
	uint64_t region_size;
	int grows_downward;
};

