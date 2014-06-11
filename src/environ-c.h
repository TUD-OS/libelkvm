#pragma once
#include <kvm.h>
#include <elkvm.h>

#ifdef __cplusplus
extern "C" {
#endif

int elkvm_initialize_env(struct elkvm_opts *opts, struct kvm_vm *vm);
guestptr_t elkvm_env_get_guest_address();
void *elkvm_env_get_host_p();

#ifdef __cplusplus
}
#endif
