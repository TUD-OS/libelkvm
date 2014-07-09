#include <cstring>
#include <memory>

#include <assert.h>
#include <signal.h>

#include <elkvm.h>
#include <elkvm-internal.h>
#include <elkvm-signal.h>
#include <flats.h>
#include <stack.h>

static int pending_signals[32];
static int num_pending_signals = 0;

namespace Elkvm {
  extern Stack stack;
  extern std::shared_ptr<VMInternals> vmi;
}

void elkvm_signal_handler(int signum) {

  printf("\n============ LIBELKVM ===========\n");
  printf(" CAUGHT SIGNAL %i\n", signum);
  printf(" SIGNALS pending: %i\n", num_pending_signals);
  printf("=================================\n");

  pending_signals[num_pending_signals] = signum;
  num_pending_signals++;

}

int elkvm_signal_register(struct kvm_vm *vm, int signum, struct sigaction *act,
    struct sigaction *oldact) {
  assert(vm != NULL);
  assert(signum < _NSIG);

  if(oldact != NULL) {
    memcpy(oldact, Elkvm::vmi->get_sig_ptr(signum).get(), sizeof(struct sigaction));
  }

  if(act != NULL) {
    memcpy(Elkvm::vmi->get_sig_ptr(signum).get(), act, sizeof(struct sigaction));

    struct sigaction sa;
    sa.sa_handler = elkvm_signal_handler;
    int err = sigemptyset(&sa.sa_mask);
    assert(err == 0);
    sa.sa_flags = 0;
    err = sigaction(signum, &sa, NULL);
    assert(err == 0);
  }

  return 0;
}

int elkvm_signal_deliver(struct kvm_vm *vm) {
  assert(vm != NULL);

  if(num_pending_signals <= 0) {
    return 0;
  }

  struct kvm_vcpu *vcpu = elkvm_vcpu_get(vm, 0);
  assert(vcpu != NULL);

  num_pending_signals--;
  int signum = pending_signals[num_pending_signals];

  /* push rax onto stack */
  Elkvm::stack.pushq(vcpu->regs.rax);

  /* push signal handler cleanup asm addr onto stack */
  Elkvm::stack.pushq(Elkvm::vmi->get_cleanup_flat()->region->guest_virtual);

  /* setup the signal handler stack frame and pass the signal number as arg */
  Elkvm::stack.pushq((uint64_t) Elkvm::vmi->get_sig_ptr(signum)->sa_handler);
  vcpu->regs.rdi = signum;

  return 0;
}
