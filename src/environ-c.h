#pragma once
#include <kvm.h>
#include <elkvm.h>

int elkvm_initialize_env(struct elkvm_opts *opts, struct kvm_vm *vm);

