#pragma once

#include <stdint.h>

struct mem_chunk {
	void *host_base_p;
	uint64_t guest_base;
	uint64_t size;
};

