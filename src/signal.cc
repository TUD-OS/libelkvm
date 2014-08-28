#include <algorithm>
#include <cstring>
#include <memory>

#include <assert.h>
#include <signal.h>

#include <elkvm.h>
#include <elkvm-internal.h>
#include <elkvm-signal.h>
#include <stack.h>
#include <vcpu.h>

static int pending_signals[32];
static int num_pending_signals = 0;

void elkvm_signal_handler(int signum) {

  printf("\n============ LIBELKVM ===========\n");
  printf(" CAUGHT SIGNAL %i\n", signum);
  printf(" SIGNALS pending: %i\n", num_pending_signals);
  printf("=================================\n");

  pending_signals[num_pending_signals] = signum;
  num_pending_signals++;

}

int elkvm_signal_register(Elkvm::VMInternals &vmi, int signum, struct sigaction *act,
    struct sigaction *oldact) {
  assert(signum < _NSIG);

  if(oldact != NULL) {
    memcpy(oldact, vmi.get_sig_ptr(signum).get(), sizeof(struct sigaction));
  }

  if(act != NULL) {
    memcpy(vmi.get_sig_ptr(signum).get(), act, sizeof(struct sigaction));

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

int elkvm_signal_deliver(Elkvm::VMInternals &vmi) {
  if(num_pending_signals <= 0) {
    return 0;
  }

  std::shared_ptr<struct kvm_vcpu> vcpu = vmi.get_vcpu(0);
  assert(vcpu != nullptr);

  num_pending_signals--;
  int signum = pending_signals[num_pending_signals];

  /* push rax onto stack */
  vcpu->push(vcpu->regs.rax);

  /* push signal handler cleanup asm addr onto stack */
  vcpu->push(vmi.get_cleanup_flat().region->guest_address());

  /* setup the signal handler stack frame and pass the signal number as arg */
  vcpu->push((uint64_t) vmi.get_sig_ptr(signum)->sa_handler);
  vcpu->regs.rdi = signum;

  return 0;
}
