#pragma once

#include <elkvm/elkvm.h>
#include <elkvm/vcpu.h>

int Elkvm::VM::handle_interrupt(struct kvm_vcpu *vcpu);

