#pragma once

#include <memory>

#include <gelf.h>

#include <region.h>

namespace Elkvm {

  class Environment {
    private:
      std::shared_ptr<Region> region;
      unsigned calc_auxv_num_and_set_auxv(char **env_p);
      Elf64_auxv_t *auxv;

    public:
      void init();
      off64_t push_auxv(struct kvm_vm *vm, char **env_p);
      int copy_and_push_str_arr_p(struct kvm_vm *vm, off64_t offset, char **str) const;
      guestptr_t get_guest_address() const { return region->guest_address(); }
      void *get_base_address() const { return region->base_address(); }

  };

//namespace Elkvm
}
