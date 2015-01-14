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
    UDis(const uint8_t *ptr) {
    #ifdef HAVE_LIBUDIS86
      ud_init(&ud_obj);
      ud_set_mode(&ud_obj, bits);
      ud_set_syntax(&ud_obj, UD_SYN_INTEL);
      ud_set_input_buffer(&ud_obj, ptr, disassembly_size);
    #endif
    }

    int disassemble() {
    #ifdef HAVE_LIBUDIS86
      return ud_disassemble(&ud_obj);
    #else
      return 0;
    #endif
    }

    std::string next_insn() {
    #ifdef HAVE_LIBUDIS86
      return ud_insn_asm(&ud_obj);
    #else
      return "";
    #endif
    }
};

//namespace Elkvm
}
