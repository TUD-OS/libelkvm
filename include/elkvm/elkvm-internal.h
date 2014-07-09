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
          int run_struct_size);
      RegionManager &get_region_manager() { return rm; }
      HeapManager &get_heap_manager() { return hm; }
      int add_cpu(int mode);
      std::shared_ptr<struct kvm_vcpu> get_vcpu(int num);

      std::shared_ptr<struct elkvm_flat> get_cleanup_flat() const;
      std::shared_ptr<struct sigaction> get_sig_ptr(unsigned sig) const;
  };

  //namespace Elkvm
}
