#include <stdint.h>

#include <elkvm.h>
#include <vcpu.h>

int kvm_vcpu_create(struct kvm_vm * vcpu, int mode) {
	return -1;
}

int kvm_vcpu_set_rip(struct kvm_vcpu * vcpu, uint64_t rip) {
	return -1;
}
