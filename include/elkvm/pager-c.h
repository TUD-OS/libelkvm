#pragma once

#ifdef __cplusplus
extern "C" {
#endif

struct kvm_vm;

struct kvm_pager {
  int free_slot_id;
};

/*
 * \brief Find the host pointer for a guest virtual address. Basically do a
 * page table walk.
*/
void *elkvm_pager_get_host_p(struct kvm_pager *, uint64_t);

/*
 * \brief Create a Mapping in Kernel Space
 * params are pager, host virtual address, writeable and executable bit
 */
guestptr_t elkvm_pager_map_kernel_page(struct kvm_pager *, void *,int, int);

#ifdef __cplusplus
}
#endif
