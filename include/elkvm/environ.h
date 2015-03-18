/* * libelkvm - A library that allows execution of an ELF binary inside a virtual
 * machine without a full-scale operating system
 * Copyright (C) 2013-2015 Florian Pester <fpester@os.inf.tu-dresden.de>, Björn
 * Döbel <doebel@os.inf.tu-dresden.de>,   economic rights: Technische Universitaet
 * Dresden (Germany)
 *
 * This file is part of libelkvm.
 *
 * libelkvm is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * libelkvm is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libelkvm.  If not, see <http://www.gnu.org/licenses/>.
 */

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
      int create(VCPU &vcpu);

  };

//namespace Elkvm
}
