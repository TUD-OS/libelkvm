#pragma once

#include <linux/kvm.h>

#define KVM_EXPECT_VERSION 12
#define KVM_DEV_PATH "/dev/kvm"

struct kvm_opts {
	int fd;
	int run_struct_size;
};

int kvm_init(struct kvm_opts *);
int kvm_cleanup(struct kvm_opts *);
