#pragma once

#include <memory>

#include <gelf.h>

#include <elfloader.h>
#include <region.h>

namespace Elkvm {

  class Environment {
    private:
      std::shared_ptr<Region> region;
      unsigned calc_auxv_num_and_set_auxv(char **env_p);
      Elf64_auxv_t *auxv;
      const ElfBinary &binary;

    public:
      Environment(const ElfBinary &bin);
      off64_t push_auxv(char **env_p);
      int copy_and_push_str_arr_p(off64_t offset, char **str) const;
      off64_t push_str_copy(off64_t offset, std::string str) const;
      guestptr_t get_guest_address() const { return region->guest_address(); }
      void *get_base_address() const { return region->base_address(); }
      int fill(struct elkvm_opts *opts, struct kvm_vm *vm);

  };

//namespace Elkvm
}
