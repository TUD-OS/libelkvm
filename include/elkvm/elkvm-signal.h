#pragma once

#include <signal.h>
#include <stdbool.h>

#include "vcpu.h"

#ifdef __cplusplus
extern "C" {
#endif

struct elkvm_signals {
  struct sigaction signals[_NSIG];
};

int elkvm_signal_init(struct kvm_vm *vm);
int elkvm_signal_register(struct kvm_vm *vm, int signum, struct sigaction *act,
    struct sigaction *oldact);
int elkvm_signal_deliver(struct kvm_vm *vm);

#ifdef __cplusplus
}
#endif
