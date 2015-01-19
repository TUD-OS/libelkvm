#include <algorithm>
#include <cstring>
#include <memory>

#include <assert.h>
#include <signal.h>

#include <elkvm/elkvm.h>
#include <elkvm/elkvm-internal.h>
#include <elkvm/stack.h>
#include <elkvm/vcpu.h>

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

int Elkvm::VM::signal_register(int signum, struct sigaction *act,
    struct sigaction *oldact) {
  assert(signum < _NSIG);

  if(oldact != NULL) {
    memcpy(oldact, const_cast<struct sigaction*>(get_sig_ptr(signum)), sizeof(struct sigaction));
  }

  if(act != NULL) {
    memcpy(const_cast<struct sigaction*>(get_sig_ptr(signum)), act, sizeof(struct sigaction));

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

int Elkvm::VM::signal_deliver() {
  if(num_pending_signals <= 0) {
    return 0;
  }

  std::shared_ptr<VCPU> vcpu = get_vcpu(0);
  assert(vcpu != nullptr);

  num_pending_signals--;
  int signum = pending_signals[num_pending_signals];

  /* push rax onto stack */
  vcpu->push(vcpu->get_reg(Elkvm::Reg_t::rax));

  /* push signal handler cleanup asm addr onto stack */
  vcpu->push(get_cleanup_flat().region->guest_address());

  /* setup the signal handler stack frame and pass the signal number as arg */
  vcpu->push((uint64_t) get_sig_ptr(signum)->sa_handler);
  vcpu->set_reg(Elkvm::Reg_t::rdi, signum);

  return 0;
}
