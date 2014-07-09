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
void *elkvm_pager_get_host_p(struct kvm_pager *, guestptr_t);

#ifdef __cplusplus
}
#endif
