#include <cstring>

#include <gelf.h>

#include <environ.h>
#include <region.h>
#include <stack.h>

namespace Elkvm {
  Environment env;
  extern RegionManager rm;

  void Environment::init() {
    /* for now the region to hold env etc. will be 12 pages large */
    region = rm.allocate_region(12 * ELKVM_PAGESIZE);
    assert(region != nullptr && "error getting memory for env");
    region->set_guest_addr(LINUX_64_STACK_BASE - region->size());
  }

  unsigned Environment::calc_auxv_num_and_set_auxv(char **env_p) {
    /* XXX this breaks, if we do not get the original envp */
    char **auxv_p = env_p;
    while(*auxv_p != NULL) {
      auxv_p++;
    }
    auxv_p++;

    auxv = (Elf64_auxv_t *)auxv_p;

    unsigned i;
    for(i = 0 ; auxv->a_type != AT_NULL; auxv++, i++);

    return i;
  }

  off64_t Environment::push_auxv(struct kvm_vm *vm, char **env_p) {
    unsigned count = calc_auxv_num_and_set_auxv(env_p);

    struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

    off64_t offset = 0;

    for(unsigned i= 0 ; i < count; auxv--, i++) {
      switch(auxv->a_type) {
        case AT_NULL:
        case AT_IGNORE:
        case AT_EXECFD:
        case AT_PHDR:
        case AT_PHENT:
        case AT_PHNUM:
        case AT_PAGESZ:
        case AT_FLAGS:
        case AT_ENTRY:
        case AT_NOTELF:
        case AT_UID:
        case AT_EUID:
        case AT_GID:
        case AT_EGID:
          /* not sure about this one, might be a pointer */
        case AT_HWCAP:
        case AT_CLKTCK:
        case AT_SECURE:
          elkvm_pushq(vm, vcpu, auxv->a_un.a_val);
          break;
        case AT_BASE:
        case AT_PLATFORM:
        case 25:
        case 31:
        case AT_SYSINFO_EHDR:
          ;
          char *target = reinterpret_cast<char *>(region->base_address()) + offset;
          guestptr_t guest_virtual = region->guest_address() + offset;
          int len = strlen((char *)auxv->a_un.a_val) + 1;
          strcpy(target, (char *)auxv->a_un.a_val);
          offset = offset + len;
          elkvm_pushq(vm, vcpu, guest_virtual);
          break;
      }
      elkvm_pushq(vm, vcpu, auxv->a_type);
    }

    return offset;
  }

  int Environment::copy_and_push_str_arr_p(struct kvm_vm *vm, off64_t offset,
      char **str) const {
    if(str == NULL) {
      return 0;
    }

    struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);

    char *target = reinterpret_cast<char *>(region->base_address()) + offset;
    guestptr_t guest_virtual = region->guest_address() + offset;
    int bytes = 0;

    //first push the environment onto the stack
    int i = 0;
    while(str[i]) {
      i++;
    }

    for(i = i - 1; i >= 0; i--) {
      int len = strlen(str[i]) + 1;

      //copy the data into the vm memory
      strcpy(target, str[i]);

      //and push the pointer for the vm
      int err = elkvm_pushq(vm, vcpu, guest_virtual);
      if(err) {
        return err;
      }

      target = target + len;
      bytes += len;
      guest_virtual = guest_virtual + len;
    }

    return bytes;
  }


//namespace Elkvm
}


#ifdef __cplusplus
extern "C" {
#endif

int elkvm_initialize_env(struct elkvm_opts *opts, struct kvm_vm *vm) {
  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);
  int err = kvm_vcpu_get_regs(vcpu);
  assert(err == 0 && "error getting vcpu");

  Elkvm::env.init();
  off64_t bytes = Elkvm::env.push_auxv(vm, opts->environ);
  off64_t bytes_total = bytes;

  elkvm_pushq(vm, vcpu, 0);
  bytes = Elkvm::env.copy_and_push_str_arr_p(vm, bytes, opts->environ);
  bytes_total = bytes_total + bytes;
  elkvm_pushq(vm, vcpu, 0);
  assert(bytes > 0);

  /* followed by argv pointers */
  bytes = Elkvm::env.copy_and_push_str_arr_p(vm, bytes, opts->argv);
  bytes_total = bytes_total + bytes;
  assert(bytes > 0);

  /* at last push argc on the stack */
  elkvm_pushq(vm, vcpu, opts->argc);

  err = kvm_vcpu_set_regs(vcpu);
  return err;
}

guestptr_t elkvm_env_get_guest_address() {
  return Elkvm::env.get_guest_address();
}

void *elkvm_env_get_host_p() {
  return Elkvm::env.get_base_address();
}

#ifdef __cplusplus
}
#endif
