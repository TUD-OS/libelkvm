#include <cstring>

#include <gelf.h>

#include <elkvm/elfloader.h>
#include <elkvm/elkvm-internal.h>
#include <elkvm/environ.h>
#include <elkvm/kvm.h>
#include <elkvm/region.h>
#include <elkvm/region_manager.h>
#include <elkvm/stack.h>
#include <elkvm/elkvm-log.h>
#include <elkvm/vcpu.h>

// the global logger object (see elkvm-log.h)
ElkvmLog globalElkvmLogger;

namespace Elkvm {

  Environment::Environment(const ElfBinary &bin, std::shared_ptr<RegionManager> rm) :
	region(nullptr),
	auxv(0),
    binary(bin)
  {
    /* for now the region to hold env etc. will be 12 pages large */
    region = rm->allocate_region(12 * ELKVM_PAGESIZE, "ELKVM Environment");
    assert(region != nullptr && "error getting memory for env");
    region->set_guest_addr(
        reinterpret_cast<guestptr_t>(region->base_address()));
    int err = rm->get_pager().map_user_page(region->base_address(),
        region->guest_address(), PT_OPT_WRITE);
    assert(err == 0 && "error mapping env region");
  }

  unsigned Environment::calc_auxv_num_and_set_auxv(char **env_p) {
    /* XXX this breaks, if we do not get the original envp */

    /* traverse past the environment */
    char **auxv_p = env_p;
    while(*auxv_p != NULL) {
      auxv_p++;
    }
    auxv_p++;

    /* now traverse past the elf auxiliary vector */
    auxv = (Elf64_auxv_t *)auxv_p;

    unsigned i;
    for(i = 0 ; auxv->a_type != AT_NULL; auxv++, i++);

    /* auxv now ponts to the AT_NULL entry at the bottom (highest address)
     * on the aux vector, we return the amount of entries - 1 */
    return i;
  }

  void Environment::fix_auxv_dynamic_values(unsigned count) {
    auto current_auxv = auxv;
    short all_set = 0;

    for(unsigned i= 0 ; i < count; current_auxv--, i++) {
      /*
       * if the binary is dynamically linked, we need to reset these types
       * so the dynamic linker loads the correct values
       */
        switch(current_auxv->a_type) {
          /* XXX add the following auxv types!
           * AT_SYSINFO_EHDR: 0x7fff848e0000
           * AT_HWCAP:        bfebfbff
           * AT_PAGESZ:       4096
           * AT_CLKTCK:       100
           * AT_PHDR:         0x400040
           * AT_PHENT:        56
           * AT_PHNUM:        8
           * AT_BASE:         0x7f0204fd2000
           * AT_FLAGS:        0x0
           * AT_ENTRY:        0x4003f0
           * AT_UID:          1000
           * AT_EUID:         1000
           * AT_GID:          1000
           * AT_EGID:         1000
           * AT_SECURE:       0
           * AT_RANDOM:       0x7fff848d9519
           * AT_EXECFN:       /home/flo/work/test_cases/build/hello
           * AT_PLATFORM:     x86_64
           */

          case AT_RANDOM:
            assert(false && "AT_RANDOM found");
            break;
          case AT_PHDR:
            current_auxv->a_un.a_val = binary.get_auxv().at_phdr;
            all_set |= 0x1;
            break;
          case AT_PHENT:
            current_auxv->a_un.a_val = binary.get_auxv().at_phent;
            all_set |= 0x2;
            break;
          case AT_PHNUM:
            current_auxv->a_un.a_val = binary.get_auxv().at_phnum;
            all_set |= 0x4;
            break;
          case AT_EXECFD:
            /* TODO maybe this needs to be removed? */
            break;
          case AT_ENTRY:
            current_auxv->a_un.a_val = binary.get_auxv().at_entry;
            all_set |= 0x8;
            break;
          case AT_BASE:
            current_auxv->a_un.a_val = binary.get_auxv().at_base;
            all_set |= 0x10;
            break;
        }
    }
    assert(all_set == 0x1F && "elf auxv is complete");
  }

  bool Environment::treat_as_int_type(int type) const {
    std::vector<int> itypes({
          AT_NULL,
          AT_IGNORE,
          AT_EXECFD,
          AT_PHDR,
          AT_PHENT,
          AT_PHNUM,
          AT_PAGESZ,
          AT_FLAGS,
          AT_ENTRY,
          AT_NOTELF,
          AT_UID,
          AT_EUID,
          AT_GID,
          AT_EGID,
          /* not sure about this one, might be a pointer */
          AT_HWCAP,
          AT_CLKTCK,
          AT_SECURE,
          AT_BASE,
        });
    auto it = std::find(itypes.begin(), itypes.end(), type);
    return it != itypes.end();
  }

  off64_t Environment::push_auxv_raw(VCPU &vcpu, unsigned count, off64_t offset) {
    for(unsigned i = 0 ; i < count; auxv--, i++) {
      if(treat_as_int_type(auxv->a_type)) {
        vcpu.push(auxv->a_un.a_val);
      } else {
        offset = push_str_copy(vcpu, offset, std::string(
              reinterpret_cast<char *>(auxv->a_un.a_val)));
      }
      vcpu.push(auxv->a_type);
    }
    return offset;
  }

  off64_t Environment::push_auxv(VCPU& vcpu, char **env_p) {
    unsigned count = calc_auxv_num_and_set_auxv(env_p);
    off64_t offset = 0;

    if(binary.get_auxv().valid) {
      fix_auxv_dynamic_values(count);
    } else {
      offset = push_auxv_raw(vcpu, count, offset);
    }

    return offset;
  }

  off64_t Environment::push_str_copy(VCPU& vcpu, off64_t offset,
      const std::string &str) const {
    char *target = reinterpret_cast<char *>(region->base_address()) + offset;
    guestptr_t guest_virtual = region->guest_address() + offset;

    off64_t bytes = str.length() + 1;
    assert((bytes + offset) < region->size());

    strcpy(target, str.c_str());
    vcpu.push(guest_virtual);

    return bytes;
  }

  off64_t Environment::copy_and_push_str_arr_p(VCPU& vcpu, off64_t offset,
      char **str) const {
    if(str == nullptr) {
      return 0;
    }

    //skip the environment on the stack
    int i = 0;
    while(str[i]) {
      i++;
    }

    for(i = i - 1; i >= 0; i--) {
      offset = push_str_copy(vcpu, offset, std::string(str[i]));
    }

    return offset;
  }


int Environment::fill(elkvm_opts *opts,
    const std::shared_ptr<VCPU>& vcpu) {
  int err = vcpu->get_regs();
  assert(err == 0 && "error getting vcpu");

  off64_t bytes = push_auxv(*vcpu, opts->environ);
  off64_t bytes_total = bytes;

  vcpu->push(0);
  bytes = copy_and_push_str_arr_p(*vcpu, bytes_total, opts->environ);
  bytes_total = bytes_total + bytes;
  vcpu->push(0);
  assert(bytes > 0);

  /* followed by argv pointers */
  bytes = copy_and_push_str_arr_p(*vcpu, bytes_total, opts->argv);
  bytes_total = bytes_total + bytes;
  assert(bytes > 0);

  /* if the binary is dynamically linked we need to ajdust some stuff */
  if(binary.is_dynamically_linked()) {
    push_str_copy(*vcpu, bytes_total, binary.get_loader());
    opts->argc++;
  }

  /* at last push argc on the stack */
  vcpu->push(opts->argc);

  err = vcpu->set_regs();
  return err;
}

//namespace Elkvm
}
