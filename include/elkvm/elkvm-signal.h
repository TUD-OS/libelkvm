#pragma once

#include <signal.h>
#include <stdbool.h>

#include <elkvm.h>

namespace Elkvm {
  class VMInternals;
}

int elkvm_signal_register(Elkvm::VMInternals &vmi, int signum, struct sigaction *act,
    struct sigaction *oldact);
int elkvm_signal_deliver(Elkvm::VMInternals &vmi);
