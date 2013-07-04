#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stropts.h>
#include <unistd.h>

#include <elkvm.h>
#include <vcpu.h>

int kvm_vcpu_create(struct kvm_vm *vm, int mode) {
	if(vm->fd <= 0) {
		return -EIO;
	}

	struct kvm_vcpu *vcpu = malloc(sizeof(struct kvm_vcpu));
	memset(&vcpu->regs, 0, sizeof(struct kvm_regs));
	memset(&vcpu->sregs, 0, sizeof(struct kvm_sregs));

	int vcpu_count = kvm_vm_vcpu_count(vm);
	vcpu->fd = ioctl(vm->fd, KVM_CREATE_VCPU, vcpu_count);
	if(vcpu->fd <= 0) {
		free(vcpu);
		return -1;
	}



	int err = kvm_vcpu_initialize_regs(vcpu, mode);
	if(err) {
		return err;
	}

	err = kvm_vcpu_add_tail(vm, vcpu);
	return err;
}

int kvm_vcpu_add_tail(struct kvm_vm *vm, struct kvm_vcpu *vcpu) {
	/* find the last entry in the vcpu list for this vm */
	struct vcpu_list *vl = vm->vcpus;
	while(vl != NULL && vl->next != NULL) {
		vl = vl->next;
	}

	struct vcpu_list *new_item = malloc(sizeof(struct vcpu_list));
	if(new_item == NULL) {
		return -ENOMEM;
	}

	new_item->next = NULL;
	new_item->vcpu = vcpu;
	if(vl == NULL) {
		vm->vcpus = new_item;
	} else {
		vl->next = new_item;
	}

	return 0;
}

int kvm_vcpu_initialize_regs(struct kvm_vcpu *vcpu, int mode) {
	switch(mode) {
		case VM_MODE_X86_64:
			return kvm_vcpu_initialize_long_mode(vcpu);
		default:
			return -1;
	}
}

int kvm_vcpu_set_rip(struct kvm_vcpu * vcpu, uint64_t rip) {
	return -1;
}

int kvm_vcpu_get_regs(struct kvm_vcpu *vcpu) {
	if(vcpu->fd < 1) {
		return -EIO;
	}

	int err = ioctl(vcpu->fd, KVM_GET_REGS, &vcpu->regs);
	if(err) {
		return -errno;
	}

	err = ioctl(vcpu->fd, KVM_GET_SREGS, &vcpu->sregs);
	if(err) {
		return -errno;
	}

	return 0;
}

int kvm_vcpu_set_regs(struct kvm_vcpu *vcpu) {
	if(vcpu->fd < 1) {
		return -EIO;
	}

	int err = ioctl(vcpu->fd, KVM_SET_REGS, &vcpu->regs);
	if(err) {
		return -errno;
	}

	err = ioctl(vcpu->fd, KVM_SET_SREGS, &vcpu->sregs);
	if(err) {
		return -errno;
	}

	return 0;
}

int kvm_vcpu_destroy(struct kvm_vm *vm, struct kvm_vcpu *vcpu) {
	struct vcpu_list *vl = vm->vcpus;
	int found = 0;

	if(vl != NULL && vl->vcpu == vcpu) {
		vm->vcpus = vl->next;
		close(vl->vcpu->fd);
		free(vl->vcpu);
		free(vl);
		return 0;
	}

	while(vl != NULL && vl->next != NULL) {
		if(vl->next->vcpu == vcpu) {
			found = 1;
			break;
		}
		vl = vl->next;
	}

	if(!found) {
		return -1;
	}

	struct vcpu_list *old = vl->next;
	vl->next = vl->next->next;
	free(old);
	close(vcpu->fd);
	free(vcpu);

	return 0;
}

int kvm_vcpu_initialize_long_mode(struct kvm_vcpu *vcpu) {

	memset(&vcpu->regs, 0, sizeof(struct kvm_regs));
	//regs.rflags = 0x00000002;

	vcpu->sregs.cr0 = VCPU_CR0_FLAG_PAGING | VCPU_CR0_FLAG_CACHE_DISABLE |
			VCPU_CR0_FLAG_NOT_WRITE_THROUGH |
			VCPU_CR0_FLAG_PROTECTED;
	vcpu->sregs.cr4 = VCPU_CR4_FLAG_PAE;
	vcpu->sregs.cr2 = vcpu->sregs.cr3 = vcpu->sregs.cr8 = 0x0;
	vcpu->sregs.efer = VCPU_EFER_FLAG_LME;

	//TODO find out why this is!
	vcpu->sregs.apic_base = 0xfee00900;

	vcpu->sregs.cs.selector = 0x1000;
	vcpu->sregs.cs.base     = 0x0;
	vcpu->sregs.cs.limit    = 0xFFFFFFFF;
	vcpu->sregs.cs.type     = 0xb;
	vcpu->sregs.cs.present  = 0x1;
	vcpu->sregs.cs.dpl      = 0x0;
	vcpu->sregs.cs.db       = 0x0;
	vcpu->sregs.cs.s        = 0x1;
	vcpu->sregs.cs.l        = 0x1;
	vcpu->sregs.cs.g        = 0x1;
	vcpu->sregs.cs.avl      = 0x0;

	vcpu->sregs.ds.selector = 0x1000;
	vcpu->sregs.ds.base     = 0x0;
	vcpu->sregs.ds.limit    = 0xFFFFFFFF;
	vcpu->sregs.ds.type     = 0x3;
	vcpu->sregs.ds.present  = 0x1;
	vcpu->sregs.ds.dpl      = 0x0;
	vcpu->sregs.ds.db       = 0x0;
	vcpu->sregs.ds.s        = 0x1;
	vcpu->sregs.ds.l        = 0x0;
	vcpu->sregs.ds.g        = 0x1;
	vcpu->sregs.ds.avl      = 0x0;

	vcpu->sregs.ss.selector = 0x1000;
	vcpu->sregs.ss.base     = 0x0;
	vcpu->sregs.ss.limit    = 0xFFFFFFFF;
	vcpu->sregs.ss.type     = 0x3;
	vcpu->sregs.ss.present  = 0x1;
	vcpu->sregs.ss.dpl      = 0x0;
	vcpu->sregs.ss.db       = 0x0;
	vcpu->sregs.ss.s        = 0x1;
	vcpu->sregs.ss.l        = 0x0;
	vcpu->sregs.ss.g        = 0x1;
	vcpu->sregs.ss.avl      = 0x0;

	memset(&vcpu->sregs.es, 0, sizeof(struct kvm_segment));
	memset(&vcpu->sregs.fs, 0, sizeof(struct kvm_segment));
	memset(&vcpu->sregs.gs, 0, sizeof(struct kvm_segment));
	memset(&vcpu->sregs.tr, 0, sizeof(struct kvm_segment));
	memset(&vcpu->sregs.ldt, 0, sizeof(struct kvm_segment));

	memset(&vcpu->sregs.gdt, 0, sizeof(struct kvm_dtable));
	memset(&vcpu->sregs.idt, 0, sizeof(struct kvm_dtable));

	int err = kvm_vcpu_set_regs(vcpu);
	return err;
}

int kvm_vcpu_singlestep(struct kvm_vcpu *vcpu) {
	struct kvm_guest_debug debug = {
		.control        = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP,
	};
	
	return ioctl(vcpu->fd, KVM_SET_GUEST_DEBUG, &debug);
}

int kvm_vcpu_run(struct kvm_vcpu *vcpu) {
	int err = ioctl(vcpu->vcpu_fd, KVM_RUN, 0); 
	if (err < 0 && (errno != EINTR && errno != EAGAIN)) {
		return -1
	}	
}
