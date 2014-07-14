#pragma once

#include <signal.h>
#include <stdbool.h>

#include "vcpu.h"

namespace Elkvm {
  class VMInternals;
}

int elkvm_signal_register(Elkvm::VMInternals &vmi, int signum, struct sigaction *act,
    struct sigaction *oldact);
int elkvm_signal_deliver(Elkvm::VMInternals &vmi);

#ifdef __cplusplus
extern "C" {
#endif

struct elkvm_signals {
  struct sigaction signals[_NSIG];
};

#ifdef __cplusplus
}
#endif
