#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define KVM_EXPECT_VERSION 12
#define KVM_DEV_PATH "/dev/kvm"

struct elkvm_opts {
	int argc;
	char **argv;
	char **environ;
	int fd;
	int run_struct_size;
};

int elkvm_init(struct elkvm_opts *, int, char **, char **);
int elkvm_cleanup(struct elkvm_opts *);

int elkvm_idt_setup(struct kvm_vm *, struct elkvm_flat *);

#ifdef __cplusplus
}
#endif
