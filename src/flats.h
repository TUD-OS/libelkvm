#pragma once

#include <inttypes.h>

#include <region.h>

struct elkvm_flat {
  std::shared_ptr<Elkvm::Region> region;
	uint64_t size;
};

