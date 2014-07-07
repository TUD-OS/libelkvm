#pragma once

#include <vector>

#include <elfloader.h>
#include <heap.h>
#include <region.h>
#include <stack.h>

namespace Elkvm {

  class VMInternals {
    private:
      struct kvm_pager pager;
      std::vector<struct kvm_vcpu *> cpus;

      HeapManager heap_m;
      RegionManager rm;
      Stack stack;

      int _vmfd;
      int _argc;
      char **_argv;
      char **_environ;
      int _run_struct_size;

    public:
      VMInternals(int fd, int argc, char **argv, char **environ, int mode);
      RegionManager &get_region_manager();
      HeapManager &get_heap_manager();
      int add_cpu(int mode);
  };

  //namespace Elkvm
}
