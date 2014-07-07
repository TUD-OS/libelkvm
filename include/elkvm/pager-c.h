#pragma once

#ifdef __cplusplus
extern "C" {
#endif

struct kvm_vm;

struct kvm_pager {
	uint64_t guest_top_pm;
	int mode;
	void *host_pml4_p;
	void *host_next_free_tbl_p;
	uint64_t guest_next_free;
  uint64_t total_memsz;
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
