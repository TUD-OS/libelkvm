#include <iostream>
#include <memory>
#include <cstring>

#include <elkvm/elkvm.h>
#include <elkvm/kvm.h>

extern char **environment;

static long
strace_pre_handler(Elkvm::VM* vm,
                   std::shared_ptr<struct kvm_vcpu> vcpu,
                   int eventtype)
{
  std::cout << "syscall_pre" << std::endl;
  return 0;
}


static long
strace_post_handler(Elkvm::VM* vm,
                    std::shared_ptr<struct kvm_vcpu> vcpu,
                    int eventtype)
{
  std::cout << "syscall_post" << std::endl;
  return 0;
}

int main(int argc, char *argv[])
{
  std::cout << "[ELKVM] Launching" << std::endl;

  Elkvm::elkvm_opts opts;
  int err = elkvm_init(&opts, argc-1, &argv[1], environ);
  if (err) {
    std::cerr << "ERROR initializing ELKVM: " << strerror(-err) << std::endl;
    return 1;
  }

  Elkvm::hypercall_handlers strace_handlers = {
    .pre_handler = strace_pre_handler,
    .post_handler = strace_post_handler
  };

  std::shared_ptr<Elkvm::VM> vm = elkvm_vm_create(&opts, argv[1], 1, &strace_handlers);
  if (vm == nullptr) {
    std::cerr << "ERROR creating VM: " << strerror(errno) << std::endl;
    return 1;
  }

  err = vm->run();
  if (err) {
    std::cerr << "Error running vCPU: " << strerror(-err) << std::endl;
    return 1;
  }

  err = elkvm_cleanup(&opts);
  if (err) {
    std::cerr << "Error during cleanup: " << strerror(-err) << std::endl;
    return 1;
  }
  
  std::cout << "[ELVKM] Terminating successfully." << std::endl;

  return 0;
}
