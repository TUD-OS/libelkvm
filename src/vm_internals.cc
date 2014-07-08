#include <cstring>

#include <sys/ioctl.h>

#include <elkvm.h>
#include <elkvm-internal.h>
#include <pager.h>
#include <vcpu.h>

namespace Elkvm {

  VMInternals::VMInternals(int vmfd, int argc, char ** argv, char **environ,
      int run_struct_size) :
    rm(vmfd),
    _vmfd(vmfd),
    _argc(argc),
    _argv(argv),
    _environ(environ),
    _run_struct_size(run_struct_size)
  {}

  int VMInternals::add_cpu(int mode) {
    std::shared_ptr<struct kvm_vcpu> vcpu = std::make_shared<struct kvm_vcpu>();
    if(vcpu == NULL) {
      return -ENOMEM;
    }

    memset(&vcpu->regs, 0, sizeof(struct kvm_regs));
    memset(&vcpu->sregs, 0, sizeof(struct kvm_sregs));
    vcpu->singlestep = 0;

    vcpu->fd = ioctl(_vmfd, KVM_CREATE_VCPU, cpus.size());
    if(vcpu->fd <= 0) {
      return -errno;
    }

    int err = kvm_vcpu_initialize_regs(vcpu.get(), mode);
    if(err) {
      return err;
    }

    vcpu->run_struct = reinterpret_cast<struct kvm_run *>(
        mmap(NULL, sizeof(struct kvm_run), PROT_READ | PROT_WRITE,
        MAP_SHARED, vcpu->fd, 0));
    if(vcpu->run_struct == NULL) {
      return -ENOMEM;
    }

#ifdef HAVE_LIBUDIS86
    elkvm_init_udis86(vcpu.get(), mode);
#endif

    cpus.push_back(vcpu);
    return 0;
  }

  std::shared_ptr<struct kvm_vcpu> VMInternals::get_vcpu(int num) {
    return cpus.at(num);
  }

  //namespace Elkvm
}
