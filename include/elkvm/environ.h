#pragma once

#include <memory>

#include <gelf.h>

#include <elkvm/elfloader.h>
#include <elkvm/region.h>

namespace Elkvm {
  class VCPU;

  class Environment {
    private:
      std::shared_ptr<Region> region;
      unsigned calc_auxv_num_and_set_auxv(char **env_p);
      Elf64_auxv_t *auxv;
      const ElfBinary &binary;

      void fix_auxv_dynamic_values(unsigned count);
    public:
      Environment(const ElfBinary &bin, std::shared_ptr<RegionManager> rm);
      off64_t push_auxv(std::shared_ptr<VCPU> vcpu, char **env_p);

      int copy_and_push_str_arr_p(std::shared_ptr<VCPU> vcpu,
          off64_t offset, char **str) const;

      off64_t push_str_copy(std::shared_ptr<VCPU> vcpu,
          off64_t offset, std::string str) const;

      guestptr_t get_guest_address() const { return region->guest_address(); }
      int fill(elkvm_opts *opts, std::shared_ptr<VCPU> vcpu);

  };

//namespace Elkvm
}
