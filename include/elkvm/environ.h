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

      bool treat_as_int_type(int type) const;
      off64_t push_str_copy(VCPU& vcpu, off64_t offset,
          const std::string &str) const;
      off64_t copy_and_push_str_arr_p(VCPU& vcpu, off64_t offset, char **str) const;

      off64_t push_auxv(VCPU& vcpu, char **env_p);
      off64_t push_auxv_raw(VCPU &vcpu, unsigned count, off64_t offset);
      void fix_auxv_dynamic_values(unsigned count);

    public:
      Environment(const ElfBinary &bin, std::shared_ptr<RegionManager> rm);
      Environment(Environment const&) = delete;
      Environment& operator=(Environment const&) = delete;



      guestptr_t get_guest_address() const { return region->guest_address(); }
      int fill(elkvm_opts *opts, const std::shared_ptr<VCPU>& vcpu);

  };

//namespace Elkvm
}
