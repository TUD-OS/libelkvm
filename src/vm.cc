#include <algorithm>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stropts.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <elkvm.h>
#include <elkvm-internal.h>
#include <debug.h>
#include <environ.h>
#include <elfloader.h>
#include <flats.h>
#include <gdt.h>
#include <idt.h>
#include <kvm.h>
#include <pager.h>
#include <vcpu.h>
namespace Elkvm {
  std::vector<VMInternals> vmi;
}

struct kvm_vm *elkvm_vm_create(struct elkvm_opts *opts, int mode,
    unsigned cpus, const struct elkvm_handlers * const handlers, const char *binary,
    int debug) {

  int err = 0;

  int vmfd = ioctl(opts->fd, KVM_CREATE_VM, 0);
  if(vmfd < 0) {
    return NULL;
  }

  int run_struct_size = ioctl(opts->fd, KVM_GET_VCPU_MMAP_SIZE, 0);
  if(run_struct_size < 0) {
    return NULL;
  }

  Elkvm::vmi.emplace_back(
      vmfd,
        opts->argc,
        opts->argv,
        opts->environ,
        run_struct_size,
        handlers,
        debug);
  Elkvm::VMInternals &vmi = Elkvm::vmi.back();

  for(unsigned i = 0; i < cpus; i++) {
    err = vmi.add_cpu(mode);
		if(err) {
      errno = -err;
			return NULL;
		}
  }

  Elkvm::ElfBinary bin(binary, vmi.get_region_manager(), vmi.get_heap_manager());

  guestptr_t entry = bin.get_entry_point();
  err = vmi.set_entry_point(entry);
  assert(err == 0);

  Elkvm::Environment env(bin, vmi.get_region_manager());

  std::shared_ptr<struct kvm_vcpu> vcpu = vmi.get_vcpu(0);

  /* gets and sets vcpu->regs */
  err = env.fill(opts, vcpu);
  assert(err == 0);

	err = elkvm_gdt_setup(*vmi.get_region_manager(), vcpu);
  assert(err == 0);

	struct elkvm_flat idth;
  std::string isr_path(RES_PATH "/isr");
	err = vmi.load_flat(idth, isr_path, 1);
	if(err) {
    if(err == -ENOENT) {
      printf("LIBELKVM: ISR shared file could not be found\n");
    }
    errno = -err;
		return NULL;
	}

	err = elkvm_idt_setup(*vmi.get_region_manager(), vcpu, &idth);
  assert(err == 0);

	struct elkvm_flat sysenter;
  std::string sysenter_path(RES_PATH "/entry");
	err = vmi.load_flat(sysenter, sysenter_path, 1);
	if(err) {
    if(err == -ENOENT) {
      printf("LIBELKVM: SYSCALL ENTRY shared file could not be found\n");
    }
    errno = -err;
		return NULL;
	}

  std::string sighandler_path(RES_PATH "/signal");
  auto sigclean = vmi.get_cleanup_flat();
  err = vmi.load_flat(sigclean, sighandler_path, 0);
  if(err) {
    if(err == -ENOENT) {
      printf("LIBELKVM: SIGNAL HANDLER shared file could not be found\n");
    }
    errno = -err;
    return NULL;
  }

	/*
	 * setup the lstar register with the syscall handler
	 */
	err = kvm_vcpu_set_msr(vmi.get_vcpu(0).get(),
			VCPU_MSR_LSTAR,
			sysenter.region->guest_address());
  assert(err == 0);

  std::shared_ptr<struct kvm_vm> vm = vmi.get_vm_ptr();
  for(int i = 0; i < RLIMIT_NLIMITS; i++) {
    err = getrlimit(i, &vm->rlimits[i]);
    assert(err == 0);
  }

  Elkvm::dump_stack(vmi, vcpu.get());

	return vm.get();
}

int elkvm_set_debug(struct kvm_vm *vm) {
  vm->debug = 1;
  return 0;
}

int elkvm_init(struct elkvm_opts *opts, int argc, char **argv, char **environ) {
	opts->argc = argc;
	opts->argv = argv;
	opts->environ = environ;

	opts->fd = open(KVM_DEV_PATH, O_RDWR);
	if(opts->fd < 0) {
		return -errno;
	}

	int version = ioctl(opts->fd, KVM_GET_API_VERSION, 0);
	if(version != KVM_EXPECT_VERSION) {
		return -ENOPROTOOPT;
	}

	opts->run_struct_size = ioctl(opts->fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	if(opts->run_struct_size <= 0) {
		return -EIO;
	}

	return 0;
}

int elkvm_cleanup(struct elkvm_opts *opts) {
	close(opts->fd);
	opts->fd = 0;
	opts->run_struct_size = 0;
	return 0;
}

int elkvm_chunk_remap(struct kvm_vm *vm, int num, uint64_t newsize) {
  Elkvm::VMInternals &vmi = Elkvm::get_vmi(vm);

  auto chunk = vmi.get_region_manager()->get_pager().get_chunk(num);
  chunk->memory_size = 0;

	int err = ioctl(vm->fd, KVM_SET_USER_MEMORY_REGION, chunk.get());
  assert(err == 0);
  free((void *)chunk->userspace_addr);
  chunk->memory_size = newsize;
  err = posix_memalign(((void **)&chunk->userspace_addr), ELKVM_PAGESIZE, chunk->memory_size);
  assert(err == 0);
	err = ioctl(vm->fd, KVM_SET_USER_MEMORY_REGION, chunk.get());
  assert(err == 0);
  return 0;
}

struct kvm_vcpu *elkvm_vcpu_get(struct kvm_vm *vm, int vcpu_id) {
  Elkvm::VMInternals &vmi = Elkvm::get_vmi(vm);

  auto vcpu = vmi.get_vcpu(vcpu_id);
  return vcpu.get();
}

uint64_t elkvm_chunk_count(struct kvm_vm *vm __attribute__((unused))) {
  Elkvm::VMInternals &vmi = Elkvm::get_vmi(vm);

  return vmi.get_region_manager()->get_pager().chunk_count();
}

struct kvm_userspace_memory_region elkvm_get_chunk(
    struct kvm_vm *vm __attribute__((unused)), int chunk) {
  Elkvm::VMInternals &vmi = Elkvm::get_vmi(vm);

  return *vmi.get_region_manager()->get_pager().get_chunk(chunk);
}

void elkvm_emulate_vmcall(struct kvm_vcpu *vcpu) {
  /* INTEL VMCALL instruction is three bytes long */
  vcpu->regs.rip +=3;
}

int elkvm_dump_valid_msrs(struct elkvm_opts *opts) {
	struct kvm_msr_list *list = reinterpret_cast<struct kvm_msr_list *>(
      malloc( sizeof(struct kvm_msr_list) + 255 * sizeof(uint32_t)));
	list->nmsrs = 255;

	int err = ioctl(opts->fd, KVM_GET_MSR_INDEX_LIST, list);
	if(err < 0) {
		free(list);
		return -errno;
	}

	for(unsigned i = 0; i < list->nmsrs; i++) {
		printf("MSR: 0x%x\n", list->indices[i]);
	}
	free(list);

	return 0;
}

