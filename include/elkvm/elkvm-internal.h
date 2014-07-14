#pragma once

#include <vector>

#include <elfloader.h>
#include <flats.h>
#include <heap.h>
#include <region.h>
#include <stack.h>

namespace Elkvm {

  class VMInternals {
    private:
      std::vector<std::shared_ptr<struct kvm_vcpu>> cpus;
      std::shared_ptr<struct kvm_vm> _vm;

      HeapManager hm;
      RegionManager rm;
      Stack stack;

      int _vmfd;
      int _argc;
      char **_argv;
      char **_environ;
      int _run_struct_size;

      struct elkvm_signals sigs;
      struct elkvm_flat sighandler_cleanup;

    public:
      VMInternals(int fd, int argc, char **argv, char **environ,
          int run_struct_size,
          const struct elkvm_handlers * const handlers,
          int debug);

      int add_cpu(int mode);

      RegionManager &get_region_manager() { return rm; }
      HeapManager &get_heap_manager() { return hm; }
      std::shared_ptr<struct kvm_vcpu> get_vcpu(int num) const;
      int get_vmfd() const { return _vmfd; }
      std::shared_ptr<struct elkvm_flat> get_cleanup_flat() const;

      const struct elkvm_handlers * get_handlers() const
        { return _vm->syscall_handlers; }

      std::shared_ptr<struct sigaction> get_sig_ptr(unsigned sig) const;
      std::shared_ptr<struct kvm_vm> get_vm_ptr() const { return _vm; }

      int debug_mode() const { return _vm->debug; }

      int set_entry_point(guestptr_t rip)
        { return kvm_vcpu_set_rip(cpus.front().get(), rip); }
  };

  bool operator==(const VMInternals &lhs, const struct kvm_vm &rhs);

  //namespace Elkvm
}
