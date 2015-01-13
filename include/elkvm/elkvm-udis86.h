#pragma once

#include <elkvm/elkvm.h>
#include <elkvm/types.h>
#include <elkvm/vcpu.h>

namespace Elkvm {

#ifdef HAVE_LIBUDIS86

void init_udis86(VCPU &vcpu);

/*
 * \brief Get the next byte of code to be executed.
 */
int get_next_code_byte(const VM &vm, VCPU &vcpu, guestptr_t guest_addr);
#endif

//namespace Elkvm
}
