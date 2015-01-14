#pragma once
#include <memory>

#include <elkvm/config.h>

#ifdef HAVE_LIBUDIS86
#include <udis86.h>
#endif

#include <elkvm/types.h>

namespace Elkvm {

class UDis {
  private:
      const unsigned bits = 64;
      const size_t disassembly_size = 40;

    #ifdef HAVE_LIBUDIS86
      ud_t ud_obj;
    #endif

  public:
      UDis(const uint8_t *ptr);
      int disassemble();
      std::string next_insn();
};

//namespace Elkvm
}
