#include <cstring>

#include <gelf.h>

#include <elfloader.h>
#include <elkvm-internal.h>
#include <environ.h>
#include <kvm.h>
#include <region.h>
#include <region_manager.h>
#include <stack.h>

namespace Elkvm {
  Environment::Environment(const ElfBinary &bin, std::shared_ptr<RegionManager> rm) :
    binary(bin)
  {
    /* for now the region to hold env etc. will be 12 pages large */
    region = rm->allocate_region(12 * ELKVM_PAGESIZE);
    assert(region != nullptr && "error getting memory for env");
    region->set_guest_addr(
        reinterpret_cast<guestptr_t>(region->base_address()));
    int err = rm->get_pager().map_user_page(region->base_address(),
        region->guest_address(), PT_OPT_WRITE);
    assert(err == 0 && "error mapping env region");
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

  off64_t Environment::push_auxv(std::shared_ptr<struct kvm_vcpu> vcpu, char **env_p) {
    unsigned count = calc_auxv_num_and_set_auxv(env_p);

    off64_t offset = 0;

    if(binary.get_auxv().valid) {
      short all_set = 0;
      for(unsigned i= 0 ; i < count; auxv--, i++) {
        /*
         * if the binary is dynamically linked, we need to reset these types
         * so the dynamic linker loads the correct values
         */
          switch(auxv->a_type) {
            case AT_PHDR:
              auxv->a_un.a_val = binary.get_auxv().at_phdr;
              all_set |= 0x1;
              break;
            case AT_PHENT:
              auxv->a_un.a_val = binary.get_auxv().at_phent;
              all_set |= 0x2;
              break;
            case AT_PHNUM:
              auxv->a_un.a_val = binary.get_auxv().at_phnum;
              all_set |= 0x4;
              break;
            case AT_EXECFD:
              /* TODO maybe this needs to be removed? */
              break;
            case AT_ENTRY:
              auxv->a_un.a_val = binary.get_auxv().at_entry;
              all_set |= 0x8;
              break;
            case AT_BASE:
              auxv->a_un.a_val = binary.get_auxv().at_base;
              all_set |= 0x10;
              break;
          }
      }
      assert(all_set == 0x1F && "elf auxv is complete");
    } else {
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
        case AT_BASE:
        /*
         * AT_BASE points to the base address of the dynamic linker
         */
          vcpu->push(auxv->a_un.a_val);
          break;
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
          vcpu->push(guest_virtual);
          break;
      }
      vcpu->push(auxv->a_type);
    }
    }

    return offset;
  }

  off64_t Environment::push_str_copy(std::shared_ptr<struct kvm_vcpu> vcpu,
      off64_t offset, std::string str) const {
    char *target = reinterpret_cast<char *>(region->base_address()) + offset;
    guestptr_t guest_virtual = region->guest_address() + offset;
    off64_t bytes = str.length() + 1;

    strcpy(target, str.c_str());

    vcpu->push(guest_virtual);
    return bytes;
  }

  int Environment::copy_and_push_str_arr_p(std::shared_ptr<struct kvm_vcpu> vcpu,
      off64_t offset, char **str) const {
    if(str == NULL) {
      return 0;
    }

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
      vcpu->push(guest_virtual);

      target = target + len;
      bytes += len;
      guest_virtual = guest_virtual + len;
    }

    return bytes;
  }


int Environment::fill(struct elkvm_opts *opts,
    std::shared_ptr<struct kvm_vcpu> vcpu) {
  int err = kvm_vcpu_get_regs(vcpu.get());
  assert(err == 0 && "error getting vcpu");

  off64_t bytes = push_auxv(vcpu, opts->environ);
  off64_t bytes_total = bytes;

  vcpu->push(0);
  bytes = copy_and_push_str_arr_p(vcpu, bytes_total, opts->environ);
  bytes_total = bytes_total + bytes;
  vcpu->push(0);
  assert(bytes > 0);

  /* followed by argv pointers */
  bytes = copy_and_push_str_arr_p(vcpu, bytes_total, opts->argv);
  bytes_total = bytes_total + bytes;
  assert(bytes > 0);

  /* if the binary is dynamically linked we need to ajdust some stuff */
  if(binary.is_dynamically_linked()) {
    push_str_copy(vcpu, bytes_total, binary.get_loader());
    opts->argc++;
  }

  /* at last push argc on the stack */
  vcpu->push(opts->argc);

  err = kvm_vcpu_set_regs(vcpu.get());
  return err;
}

//namespace Elkvm
}
