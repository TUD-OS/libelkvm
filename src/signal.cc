//
// libelkvm - A library that allows execution of an ELF binary inside a virtual
// machine without a full-scale operating system
// Copyright (C) 2013-2015 Florian Pester <fpester@os.inf.tu-dresden.de>, Björn
// Döbel <doebel@os.inf.tu-dresden.de>,   economic rights: Technische Universitaet
// Dresden (Germany)
//
// This file is part of libelkvm.
//
// libelkvm is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// libelkvm is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with libelkvm.  If not, see <http://www.gnu.org/licenses/>.
//

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

  if(32 <= signum && signum <= 64) {
    /* these are real-time signals, we need to adjust the signal number,
     * because this is what the libc did, before the ELKVM proxy kernel
     * got the syscall, we need to adjust these back
     * XXX this is a crude and poorly understood hack! */
    signum = signum % 32;
    signum += SIGRTMIN;
  }

  if(oldact != nullptr) {
    memcpy(oldact, const_cast<struct sigaction*>(get_sig_ptr(signum)),
        sizeof(struct sigaction));
  }

  if(act != nullptr) {
    memcpy(const_cast<struct sigaction*>(get_sig_ptr(signum)), act,
        sizeof(struct sigaction));

    struct sigaction sa;
    sa.sa_handler = elkvm_signal_handler;
    int err = sigemptyset(&sa.sa_mask);
    assert(err == 0);
    sa.sa_flags = 0;
    err = sigaction(signum, &sa, NULL);
    if(err) {
      ERROR() << "Error during sigaction: " << std::dec << err
              << " Msg: " << strerror(errno);
    }
    assert(err == 0);
  }

  return 0;
}

int Elkvm::VM::signal_deliver() {
  if(num_pending_signals <= 0) {
    return 0;
  }

  const auto & vcpu = get_vcpu(0);
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
