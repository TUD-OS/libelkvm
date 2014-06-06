#pragma once

#include <linux/kvm.h>
#include <gelf.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KVM_EXPECT_VERSION 12
#define KVM_DEV_PATH "/dev/kvm"

struct kvm_vm;
struct elkvm_memory_region;

struct elkvm_opts {
	int argc;
	char **argv;
	char **environ;
	int fd;
	int run_struct_size;
};

int elkvm_init(struct elkvm_opts *, int, char **, char **);
int elkvm_cleanup(struct elkvm_opts *);

/*
 * Initialize the Stack as the Linux kernel would do
 */
int elkvm_initialize_stack(struct elkvm_opts *, struct kvm_vm *);

int elkvm_push_auxv(struct kvm_vm *, struct elkvm_memory_region *, Elf64_auxv_t *, int);
/*
 * Copy a string array into the VM memory and push it's location to the stack
 */
int elkvm_copy_and_push_str_arr_p(struct kvm_vm *vm, struct elkvm_memory_region *,
    uint64_t, char **str);

#ifdef __cplusplus
}
#endif
