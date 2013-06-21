#pragma once

#include <linux/kvm.h>

struct kvm_vcpu {
	int fd;
	struct kvm_regs regs;
	struct kvm_sregs sregs;
}

/*
	Creates a runnable VCPU in the mode given by the parameter
*/
int kvm_vcpu_create(struct kvm_vcpu *, int);

/*
	Set the VCPU's rip to a specific value
*/
int kvm_vcpu_set_rip(struct kvm_vcpu *, uint64_t);
