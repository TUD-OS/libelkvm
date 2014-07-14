#include <cstring>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <elkvm.h>
#include <elkvm-internal.h>
#include <pager.h>
#include <vcpu.h>

namespace Elkvm {

  VMInternals::VMInternals(int vmfd, int argc, char ** argv, char **environ,
      int run_struct_size,
      const struct elkvm_handlers * const handlers,
      int debug) :
    rm(vmfd),
    _vmfd(vmfd),
    _argc(argc),
    _argv(argv),
    _environ(environ),
    _run_struct_size(run_struct_size)
  {
    _vm = std::make_shared<struct kvm_vm>();
    _vm->fd = _vmfd;
    _vm->syscall_handlers = handlers;
    _vm->debug = debug;
  }

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

  int VMInternals::load_flat(struct elkvm_flat &flat, const std::string path,
      bool kernel) {
    int fd = open(path.c_str(), O_RDONLY);
    if(fd < 0) {
      return -errno;
    }

    struct stat stbuf;
    int err = fstat(fd, &stbuf);
    if(err) {
      close(fd);
      return -errno;
    }

    flat.size = stbuf.st_size;
    std::shared_ptr<Elkvm::Region> region = rm.allocate_region(stbuf.st_size);

    if(kernel) {
      guestptr_t addr = rm.get_pager().map_kernel_page(
          region->base_address(),
          PT_OPT_EXEC);
      if(addr == 0x0) {
        close(fd);
        return -ENOMEM;
      }
      region->set_guest_addr(addr);
    } else {
      /* XXX this will break! */
      region->set_guest_addr(0x1000);
      err = rm.get_pager().map_user_page(
          region->base_address(),
          region->guest_address(),
          PT_OPT_EXEC);
      assert(err == 0);
    }

    char *buf = reinterpret_cast<char *>(region->base_address());
    int bufsize = ELKVM_PAGESIZE;
    int bytes = 0;
    while((bytes = read(fd, buf, bufsize)) > 0) {
      buf += bytes;
    }

    close(fd);
    flat.region = region;

    return 0;
  }

  std::shared_ptr<struct kvm_vcpu> VMInternals::get_vcpu(int num) const {
    return cpus.at(num);
  }

  struct elkvm_flat &VMInternals::get_cleanup_flat() {
    return sighandler_cleanup;
  }

  std::shared_ptr<struct sigaction> VMInternals::get_sig_ptr(unsigned sig) const {
    return std::make_shared<struct sigaction>(sigs.signals[sig]);
  }

  bool operator==(const VMInternals &lhs, const struct kvm_vm &rhs) {
    return lhs.get_vmfd() == rhs.fd;
  }

  //namespace Elkvm
}
