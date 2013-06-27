#pragma once

#include <linux/kvm.h>

#include <elkvm.h>

#define VCPU_CR0_FLAG_PAGING            0x80000000
#define VCPU_CR0_FLAG_CACHE_DISABLE     0x40000000
#define VCPU_CR0_FLAG_NOT_WRITE_THROUGH 0x20000000
#define VCPU_CR0_FLAG_PROTECTED         0x1

#define VCPU_CR4_FLAG_PAE 0x20

#define VCPU_EFER_FLAG_LME 0x100

struct kvm_vcpu {
	int fd;
	struct kvm_regs regs;
	struct kvm_sregs sregs;
};

struct vcpu_list {
	struct kvm_vcpu *vcpu;
	struct vcpu_list *next;
};

/*
	Creates a runnable VCPU in the mode given by the parameter
*/
int kvm_vcpu_create(struct kvm_vm *, int);

/*
	Add a new VCPU entry to the tail of the VCPU list
*/
int kvm_vcpu_add_tail(struct kvm_vm *, struct kvm_vcpu *);

/*
	Remove and clean up the VCPU
*/
int kvm_vcpu_destroy(struct kvm_vm *, struct kvm_vcpu *);

/*
	Set the VCPU's rip to a specific value
*/
int kvm_vcpu_set_rip(struct kvm_vcpu *, uint64_t);

/*
	Get the VCPU's registers
*/
int kvm_vcpu_get_regs(struct kvm_vcpu *);

/*
	Set the VCPU's registers
*/
int kvm_vcpu_set_regs(struct kvm_vcpu *);

/*
	Initialize a VCPU's registers according to mode
*/
int kvm_vcpu_initialize_regs(struct kvm_vcpu *, int);

/*
	Initialize the VCPU registers for long mode
*/
int kvm_vcpu_initialize_long_mode(struct kvm_vcpu *);

