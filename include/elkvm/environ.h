#pragma once

#include <memory>

#include <gelf.h>

#include <elkvm/elfloader.h>
#include <elkvm/region.h>

namespace Elkvm {
  class VCPU;

  class EnvRegion {
    private:
      std::shared_ptr<Region> _region;
      off64_t _offset;

    public:
      EnvRegion(std::shared_ptr<Region> r);
      guestptr_t write_str(const std::string &str);

      /* TODO remove these */
      void *base_address() const { return _region->base_address(); }
      guestptr_t guest_address() const { return _region->guest_address(); }
      size_t size() const { return _region->size(); }

  };

  class Environment {
    private:
      EnvRegion _region;
      std::vector<Elf64_auxv_t> _auxv;
      std::vector<std::string> _env;
      std::vector<std::string> _argv;
      int _argc;

      const ElfBinary &binary;

      Elf64_auxv_t *calc_auxv(char **env) const;
      void fill_argv(char **argv);
      void fill_env(char **env);
      void fill_auxv(Elf64_auxv_t *auxv);
      void fix_auxv_dynamic_values();

      bool treat_as_int_type(int type) const;
      bool ignored_type(int type) const;
      void push_str_copy(VCPU& vcpu, const std::string &str);
      off64_t copy_and_push_str_arr_p(VCPU& vcpu, off64_t offset, char **str) const;

      void push_auxv_raw(VCPU &vcpu);

      void push_auxv(VCPU& vcpu);
      void push_env(VCPU& vcpu);
      void push_argv(VCPU& vcpu);
      void push_argc(VCPU& vcpu) const;

    public:
      Environment(const ElfBinary &bin, std::shared_ptr<Region> reg, int argc,
          char **argv, char **env);
      Environment(Environment const&) = delete;
      Environment& operator=(Environment const&) = delete;



      guestptr_t get_guest_address() const { return _region.guest_address(); }
      int create(VCPU &vcpu);

  };

//namespace Elkvm
}
