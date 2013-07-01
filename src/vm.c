#include <linux/kvm.h>

#include <errno.h>
#include <fcntl.h>
#include <stropts.h>
#include <sys/stat.h>
#include <unistd.h>

#include <kvm.h>
#include <pager.h>
#include <vcpu.h>
#include <elkvm.h>

int kvm_vm_create(struct kvm_opts *opts, struct kvm_vm *vm, int mode, int cpus, int memory_size) {
	if(opts->fd <= 0) {
		return -EIO;
	}

	vm->fd = ioctl(opts->fd, KVM_CREATE_VM, 0);
	if(vm->fd < 0) {
		return -errno;
	}

	int err = kvm_pager_initialize(vm, mode);
	if(err) {
		return err;
	}

	err = kvm_pager_create_mem_chunk(&vm->pager, memory_size, ELKVM_USER_CHUNK_OFFSET);
	if(err) {
		return err;
	}

	for(int i = 0; i < cpus; i++) {
		err = kvm_vcpu_create(vm, mode);
		if(err) {
			return err;
		}
	}

	return 0;
}

int kvm_check_cap(struct kvm_opts *kvm, int cap) {
	if(kvm->fd < 1) {
		return -EIO;
	}

	int r = ioctl(kvm->fd, KVM_CHECK_EXTENSION, cap);
	if(r < 0) {
		return -errno;
	}
	return r;
}

int kvm_vm_vcpu_count(struct kvm_vm *vm) {
	int count = 0;
	struct vcpu_list *vl = vm->vcpus;
	if(vl == NULL) {
		return 0;
	}

	while(vl != NULL) {
		if(vl->vcpu != NULL) {
			count++;
		}
		vl = vl->next;
	}
	return count;
}

int kvm_vm_destroy(struct kvm_vm *vm) {
	return -1;
}

int kvm_init(struct kvm_opts *opts) {
	opts->fd = open(KVM_DEV_PATH, O_RDWR);
	if(opts->fd < 0) {
		return opts->fd;
	}

	int version = ioctl(opts->fd, KVM_GET_API_VERSION, 0);
	if(version != KVM_EXPECT_VERSION) {
		return -1;
	}

	opts->run_struct_size = ioctl(opts->fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	if(opts->run_struct_size <= 0) {
		return -1;
	}

	return 0;
}

int kvm_cleanup(struct kvm_opts *opts) {
	close(opts->fd);
	opts->fd = 0;
	opts->run_struct_size = 0;
	return 0;
}

int kvm_vm_map_chunk(struct kvm_vm *vm, struct kvm_userspace_memory_region *chunk) {
	return -1;
}
