#pragma once

#ifdef __cplusplus
extern "C" {
#endif

struct elkvm_memory_region {
       void *host_base_p;
       uint64_t guest_virtual;
       uint64_t region_size;
       int grows_downward;
       int used;
       struct elkvm_memory_region *lc;
       struct elkvm_memory_region *rc;
};

struct elkvm_memory_region *elkvm_region_create(uint64_t req_size);
int elkvm_region_free(struct elkvm_memory_region *region);
int elkvm_init_region_manager(struct kvm_pager *const pager);

#ifdef __cplusplus
}
#endif

