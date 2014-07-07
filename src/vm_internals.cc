#include <sys/ioctl.h>

#include <elkvm.h>
#include <elkvm-internal.h>
#include <pager.h>

namespace Elkvm {

  VMInternals::VMInternals(int fd, int argc, char ** argv, char **environ) :
    _argc(argc),
    _argv(argv),
    _environ(environ)
  {
	  if(fd <= 0) {
      throw;
	  }

	  _vmfd = ioctl(fd, KVM_CREATE_VM, 0);
	  if(_vmfd < 0) {
      throw;
	  }

	  _run_struct_size = ioctl(fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	  if(_run_struct_size < 0) {
      throw;
	  }

    elkvm_pager_initialize();
  }



  //namespace Elkvm
}
