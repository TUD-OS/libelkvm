#pragma once

#if 1
#include <vector>

#include <elkvm-signal.h>
#include <elfloader.h>
#include <heap.h>
#include <region.h>
#include <region_manager.h>
#include <stack.h>

namespace Elkvm {

#if 0
  class VMInternals {
    private:
      std::vector<std::shared_ptr<struct kvm_vcpu>> cpus;
      std::shared_ptr<Elkvm::kvm_vm> _vm;

      std::shared_ptr<RegionManager> _rm;
      HeapManager hm;

      int _vmfd;
      int _argc;
      char **_argv;
      char **_environ;
      int _run_struct_size;

      struct elkvm_signals sigs;
      Elkvm::elkvm_flat sighandler_cleanup;

    public:
      VMInternals(int fd, int argc, char **argv, char **environ,
          int run_struct_size,
          const Elkvm::elkvm_handlers * const handlers,
          int debug);

      int add_cpu(int mode);

      bool address_mapped(guestptr_t addr) const;
      Mapping &find_mapping(guestptr_t addr);

      int load_flat(Elkvm::elkvm_flat &flat, const std::string path,
          bool kernel);

      std::shared_ptr<RegionManager> get_region_manager() { return _rm; }
      HeapManager &get_heap_manager() { return hm; }
      std::shared_ptr<struct kvm_vcpu> get_vcpu(int num) const;
      int get_vmfd() const { return _vmfd; }
      Elkvm::elkvm_flat &get_cleanup_flat();

      const Elkvm::elkvm_handlers * get_handlers() const
        { return _vm->syscall_handlers; }

      std::shared_ptr<struct sigaction> get_sig_ptr(unsigned sig) const;
      std::shared_ptr<Elkvm::kvm_vm> get_vm_ptr() const { return _vm; }

      int debug_mode() const { return _vm->debug; }

      int set_entry_point(guestptr_t rip)
        { return kvm_vcpu_set_rip(cpus.front().get(), rip); }
  };
#endif
  bool operator==(const VMInternals &lhs, const Elkvm::kvm_vm &rhs);
  VMInternals &get_vmi(Elkvm::kvm_vm *vm);

  unsigned get_hypercall_type(VMInternals &, std::shared_ptr<struct kvm_vcpu>);

  unsigned get_hypercall_type(VMInternals &, std::shared_ptr<struct kvm_vcpu>);
  
  //namespace Elkvm
}
#endif
