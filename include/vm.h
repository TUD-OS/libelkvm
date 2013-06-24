#pragma once

#include <libelf.h>

#define VM_MODE_X86    1
#define VM_MODE_PAGING 2
#define VM_MODE_X86_64 3

struct kvm_vm {
	int fd;
	struct kvm_vcpu *vcpu;
	struct pager pager;
}

/*
	Create a new VM, with the given mode, cpu count and memory
	Return 0 on success, -1 on error
*/
int kvm_vm_create(struct kvm_vm *, int, int, int);

/*
	Load an ELF binary, given by the filename into the VM
*/
int kvm_vm_load_binary(struct kvm_vm *, const char *);

/*
	Writes the state of the VM to a given file descriptor
*/
void kvm_dump_vm(struct kvm_vm *, int);

int kvm_vm_destroy(struct kvm_vm *);
