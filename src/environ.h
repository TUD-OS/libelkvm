#pragma once

#include <memory>

#include <gelf.h>

#include <region.h>

namespace Elkvm {

  class Environment {
    private:
      std::shared_ptr<Region> region;
      unsigned calc_auxv_num_and_set_auxv();
      Elf64_auxv_t *auxv;

    public:
      void init();
      off64_t push_auxv();
      int copy_and_push_str_arr_p(off64_t offset, char **str);

  };

//namespace Elkvm
}
