#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <sys/ioctl.h>

#include <elkvm.h>
#include "debug.h"

int elkvm_handle_debug(struct kvm_vm *vm) {
  int handled = 0;
  if(vm->syscall_handlers->bp_callback != NULL) {
    handled = vm->syscall_handlers->bp_callback(vm);
  }

  return handled;
}

int elkvm_debug_enable(struct kvm_vcpu *vcpu) {
  vcpu->debug.control |= KVM_GUESTDBG_ENABLE;

  return elkvm_set_guest_debug(vcpu);
}

int elkvm_debug_singlestep(struct kvm_vcpu *vcpu) {
  vcpu->debug.control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP;
  vcpu->singlestep = 1;

  return elkvm_set_guest_debug(vcpu);
}

int elkvm_debug_singlestep_off(struct kvm_vcpu *vcpu) {
  vcpu->debug.control &= ~KVM_GUESTDBG_SINGLESTEP;
  vcpu->singlestep = 0;
  return elkvm_set_guest_debug(vcpu);
}

int elkvm_set_guest_debug(struct kvm_vcpu *vcpu) {
  return ioctl(vcpu->fd, KVM_SET_GUEST_DEBUG, &vcpu->debug);
}

        printf("\tp <addr>\tPrint String at Address\n");
        printf("Be CAREFUL with your inputs, this doesn't really verify ANYTHING!\n");
        break;
      case 'p':
        ;
        uint64_t addr = atol(op + 2);
        uint64_t *host_p = kvm_pager_get_host_p(&vm->pager, addr);
        if(host_p == NULL) {
          printf("ERROR: Address not mapped!\n");
          break;
        }
        printf("%s\n", host_p);
void elkvm_dump_memory(struct kvm_vm *vm, uint64_t addr) {
  assert(addr != 0x0 && "cannot dump address NULL");
  uint64_t *host_p = elkvm_pager_get_host_p(&vm->pager, addr);
  assert(host_p != NULL && "cannot dump unmapped memory");

  fprintf(stderr, " Host Address\tGuest Address\t\tValue\t\tValue\n");
  for(int i = 0; i < 16; i++) {
    fprintf(stderr, " %p\t0x%016lx\t0x%016lx\t0x%016lx\n",
        host_p, addr,
        *host_p, *(host_p+1));
    addr  += 0x10;
    host_p+=2;
  }
}
  }
