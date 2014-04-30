#include "region.h"

namespace Elkvm {

  Region &RegionManager::allocate_region(size_t size) {
    int list_idx = 0;
    if(size <= 0x1000) {
      list_idx = 0;
    } else if(size <= 0x2000) {
      list_idx = 1;
    } else if(size <= 0x4000) {
      list_idx = 2;
    } else if(size <= 0x8000) {
      list_idx = 3;
    } else if(size <= 0x10000) {
      list_idx = 4;
    } else if(size <= 0x20000) {
      list_idx = 5;
    } else if(size <= 0x40000) {
      list_idx = 6;
    } else if(size <= 0x80000) {
      list_idx = 7;
    } else if(size <= 0x100000) {
      list_idx = 8;
    } else if(size <= 0x200000) {
      list_idx = 9;
    } else if(size <= 0x400000) {
      list_idx = 10;
    } else if(size <= 0x800000) {
      list_idx = 11;
    } else if(size <= 0x1000000) {
      list_idx = 12;
    } else if(size <= 0x2000000) {
      list_idx = 13;
    } else if(size <= 0x4000000) {
      list_idx = 14;
    }
    /* TODO requests larger than ELKVM_GROW_SIZE */

    auto &freelist = freelists[list_idx];
    while(freelist.empty()) {
      list_idx++;
      if(list_idx > freelists.size()) {
        break;
      }

      freelist = freelists[list_idx];
      /* TODO region must be split */
    }
    /* TODO what if no freelist contained a valid entry */

    Region &r = freelist.back();
    freelist.pop_back();
    r.set_used();
    return r;

  }

  int RegionManager::add_chunk(struct kvm_pager *pager, uint64_t size) {
    void *chunk_p;
    uint64_t grow_size = size > ELKVM_SYSTEM_MEMGROW ?
      pagesize_align(size) : ELKVM_SYSTEM_MEMGROW;

    int err = kvm_pager_create_mem_chunk(pager, &chunk_p, grow_size);
    if(err) {
      return err;
    }

    freelists[14].push_back(Region(chunk_p, grow_size));
    return 0;
  }

  void RegionManager::free_region(void *host_p, size_t sz) {
    /* TODO add region to freelist */
    assert(false && "not implemented");
  }

//namespace Elkvm
}


