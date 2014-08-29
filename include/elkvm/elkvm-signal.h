#pragma once

#include <signal.h>
#include <stdbool.h>

#include <elkvm.h>

int elkvm_signal_register(Elkvm::VM &vmi, int signum, struct sigaction *act,
    struct sigaction *oldact);
int elkvm_signal_deliver(Elkvm::VM &vmi);
