#include <algorithm>
#include <cstring>
#include <memory>
#include <string>
#include <vector>
#include <list>

#include <errno.h>
#include <fcntl.h>
#include <stropts.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <elkvm/config.h>
#include <elkvm/elkvm.h>
#include <elkvm/elkvm-internal.h>
#include <elkvm/elkvm-log.h>
#include <elkvm/debug.h>
#include <elkvm/environ.h>
#include <elkvm/elfloader.h>
#include <elkvm/gdt.h>
#include <elkvm/idt.h>
#include <elkvm/kvm.h>
#include <elkvm/pager.h>
#include <elkvm/vcpu.h>

namespace Elkvm {

std::list<std::shared_ptr<Elkvm::VM> > vmi;


int VM::run() {
  bool is_running = 1;
  auto vcpu = get_vcpu(0);
  while(is_running) {
    int err = vcpu->set_regs();
    if(err) {
      return err;
    }

    int exit_reason = vcpu->run();
    if(exit_reason < 0) {
      return exit_reason;
    }

    err = vcpu->get_regs();
    if(err) {
      return err;
    }

    vcpu->print_info(*this);
    if(exit_reason == VCPU::hypercall_exit) {
      int err = handle_hypercall(vcpu);
      if(err) {
        is_running = false;
      }
    } else {
      is_running = vcpu->handle_vm_exit();
    }
  }
  return 0;
}


std::shared_ptr<VM> create_virtual_hardware(const elkvm_opts * const opts,
        const Elkvm::hypercall_handlers * const hyp,
        const Elkvm::elkvm_handlers * const handlers,
        unsigned cpus,
        int mode) {
  (void)mode; // unused warning...
  auto vm = create_vm_object(opts, hyp, handlers);
  assert(vm != nullptr && "error creating vm object");

  int err = create_vcpus(vm, cpus);
  assert(err == 0 && "error creating vcpus");

  return vm;
}


int load_elf_binary(const std::shared_ptr<VM>& vm,
        elkvm_opts * opts,
        const std::string binary) {

  Elkvm::ElfBinary bin(binary, vm->get_region_manager(), vm->get_heap_manager());

  auto vcpu = vm->get_vcpu(0);
  vcpu->set_entry_point(bin.get_entry_point());

  int err = create_and_setup_environment(bin, vm, opts, vcpu);
  assert(err == 0  && "error creating environment");

  return 0;
}

int setup_proxy_os(const std::shared_ptr<VM>& vm) {
  auto vcpu = vm->get_vcpu(0);

  std::shared_ptr<Elkvm::Region> gdt = elkvm_gdt_setup(*vm->get_region_manager(), vcpu);
  assert(gdt && "error setting up global descriptor tables");

  int err = create_idt(vm, vcpu);
  assert(err == 0 && "error creating idt");

  err = create_sysenter(vm, vcpu);
  assert(err == 0 && "error loading sysenter routines");

  err = create_sighandler(vm);
  assert(err == 0 && "error loading signal handler");

  vm->init_rlimits();
  assert(err == 0 && "error initializing rlimits");

  return 0;
}


int create_vcpus(const std::shared_ptr<VM>& vm, unsigned cpus) {
  for(unsigned i = 0; i < cpus; i++) {
    int err = vm->add_cpu();
    if(err) {
      return err;
    }
  }
  return 0;
}

int create_idt(const std::shared_ptr<VM>& vm,
    const std::shared_ptr<VCPU> vcpu) {
  Elkvm::elkvm_flat idth;

  std::string isr_path(RES_PATH "/isr");
  int err = vm->load_flat(idth, isr_path, 1);
  if(err) {
    return err;
  }

  return elkvm_idt_setup(*vm->get_region_manager(), vcpu, &idth);
}

int create_sysenter(const std::shared_ptr<VM>& vm,
    const std::shared_ptr<VCPU> vcpu) {
  Elkvm::elkvm_flat sysenter;
  std::string sysenter_path(RES_PATH "/entry");
  int err = vm->load_flat(sysenter, sysenter_path, 1);
  if(err) {
    return err;
  }

  /*
   * setup the lstar register with the syscall handler
   */
  vcpu->set_msr(VCPU_MSR_LSTAR, sysenter.region->guest_address());
  return 0;
}

int create_sighandler(const std::shared_ptr<VM>& vm) {
  std::string sighandler_path(RES_PATH "/signal");
  auto sigclean = vm->get_cleanup_flat();
  return vm->load_flat(sigclean, sighandler_path, 0);
}

void VM::unpack_syscall(CURRENT_ABI::paramtype *arg) {
  *arg = CURRENT_ABI::get_parameter(get_vcpu(0), 1);
}

void VM::unpack_syscall(CURRENT_ABI::paramtype *arg1,
    CURRENT_ABI::paramtype *arg2) {
  *arg1 = CURRENT_ABI::get_parameter(get_vcpu(0), 1);
  *arg2 = CURRENT_ABI::get_parameter(get_vcpu(0), 2);
}

void VM::unpack_syscall(CURRENT_ABI::paramtype *arg1,
    CURRENT_ABI::paramtype *arg2,
    CURRENT_ABI::paramtype *arg3) {
  *arg1 = CURRENT_ABI::get_parameter(get_vcpu(0), 1);
  *arg2 = CURRENT_ABI::get_parameter(get_vcpu(0), 2);
  *arg3 = CURRENT_ABI::get_parameter(get_vcpu(0), 3);
}

void VM::unpack_syscall(CURRENT_ABI::paramtype *arg1,
    CURRENT_ABI::paramtype *arg2,
    CURRENT_ABI::paramtype *arg3,
    CURRENT_ABI::paramtype *arg4) {
  *arg1 = CURRENT_ABI::get_parameter(get_vcpu(0), 1);
  *arg2 = CURRENT_ABI::get_parameter(get_vcpu(0), 2);
  *arg3 = CURRENT_ABI::get_parameter(get_vcpu(0), 3);
  *arg4 = CURRENT_ABI::get_parameter(get_vcpu(0), 4);
}

void VM::unpack_syscall(CURRENT_ABI::paramtype *arg1,
    CURRENT_ABI::paramtype *arg2,
    CURRENT_ABI::paramtype *arg3,
    CURRENT_ABI::paramtype *arg4,
    CURRENT_ABI::paramtype *arg5) {
  *arg1 = CURRENT_ABI::get_parameter(get_vcpu(0), 1);
  *arg2 = CURRENT_ABI::get_parameter(get_vcpu(0), 2);
  *arg3 = CURRENT_ABI::get_parameter(get_vcpu(0), 3);
  *arg4 = CURRENT_ABI::get_parameter(get_vcpu(0), 4);
  *arg5 = CURRENT_ABI::get_parameter(get_vcpu(0), 5);
}

void VM::unpack_syscall(CURRENT_ABI::paramtype *arg1,
    CURRENT_ABI::paramtype *arg2,
    CURRENT_ABI::paramtype *arg3,
    CURRENT_ABI::paramtype *arg4,
    CURRENT_ABI::paramtype *arg5,
    CURRENT_ABI::paramtype *arg6) {
  *arg1 = CURRENT_ABI::get_parameter(get_vcpu(0), 1);
  *arg2 = CURRENT_ABI::get_parameter(get_vcpu(0), 2);
  *arg3 = CURRENT_ABI::get_parameter(get_vcpu(0), 3);
  *arg4 = CURRENT_ABI::get_parameter(get_vcpu(0), 4);
  *arg5 = CURRENT_ABI::get_parameter(get_vcpu(0), 5);
  *arg6 = CURRENT_ABI::get_parameter(get_vcpu(0), 6);
}
int VM::init_rlimits()
{
  for (unsigned i = 0; i < RLIMIT_NLIMITS; ++i) {
    int err = ::getrlimit(i, &_vm.rlimits[i]);
    if(err) {
      return err;
    }
  }
  return 0;
}

std::shared_ptr<VM> create_vm_object(const elkvm_opts * const opts,
        const Elkvm::hypercall_handlers * const hyp,
        const Elkvm::elkvm_handlers * const handlers) {

  int vmfd = ioctl(opts->fd, KVM_CREATE_VM, 0);
  if(vmfd < 0) {
    return NULL;
  }

  int run_struct_size = ioctl(opts->fd, KVM_GET_VCPU_MMAP_SIZE, 0);
  if(run_struct_size < 0) {
    return NULL;
  }

  std::shared_ptr<Elkvm::VM> vmi = std::make_shared<Elkvm::VM>(
        vmfd,
        opts->argc,
        opts->argv,
        opts->environ,
        run_struct_size,
        hyp,
        handlers,
        opts->debug);
  Elkvm::vmi.push_back(vmi);

  return vmi;
}

int create_and_setup_environment(const ElfBinary &bin,
    const std::shared_ptr<VM>& vm,
    elkvm_opts * opts,
    const std::shared_ptr<VCPU>& vcpu) {

  auto &rm = *vm->get_region_manager();
  /* for now the region to hold env etc. will be 12 pages large */
  auto r = rm.allocate_region(12 * ELKVM_PAGESIZE, "ELKVM Environment");
  assert(r != nullptr && "error getting memory for env");

  Elkvm::Environment env(bin, r);

  int err = rm.get_pager().map_user_page(r->base_address(),
      r->guest_address(), PT_OPT_WRITE);
  assert(err == 0 && "error mapping env region");

  /* gets and sets vcpu->regs */
  return env.fill(opts, vcpu);
}

//namespace Elkvm
}

std::shared_ptr<Elkvm::VM>
elkvm_vm_create_raw(Elkvm::elkvm_opts *opts,
                    unsigned cpus,
                    const Elkvm::hypercall_handlers * const hyp,
                    const Elkvm::elkvm_handlers * const handlers,
                    int mode,
                    bool debug)
{
  int err = 0;
  opts->debug = debug;

  auto vmi = Elkvm::create_virtual_hardware(opts, hyp, handlers, cpus, mode);
  assert(vmi != nullptr && "error creating virtual hardware");

  err = Elkvm::setup_proxy_os(vmi);
  assert(err == 0 && "error setting up proxy os");

  return vmi;
}


std::shared_ptr<Elkvm::VM>
elkvm_vm_create(Elkvm::elkvm_opts *opts,
                const char *binary,
                unsigned cpus,
                const Elkvm::hypercall_handlers * const hyp,
                const Elkvm::elkvm_handlers * const handlers,
                int mode,
                bool debug) {

  int err = 0;
  opts->debug = debug;

  auto vmi = Elkvm::create_virtual_hardware(opts, hyp, handlers, cpus, mode);
  assert(vmi != nullptr && "error creating virtual hardware");

  err = Elkvm::load_elf_binary(vmi, opts, binary);
  assert(err == 0 && "error loading elf binary");

  err = Elkvm::setup_proxy_os(vmi);
  assert(err == 0 && "error setting up proxy os");

  return vmi;
}

int Elkvm::VM::chunk_remap(int num, size_t newsize) {

  auto chunk = get_region_manager()->get_pager().get_chunk(num);
  chunk->memory_size = 0;

  int err = ioctl(get_vmfd(), KVM_SET_USER_MEMORY_REGION, chunk.get());
  assert(err == 0);
  free((void *)chunk->userspace_addr);
  chunk->memory_size = newsize;
  err = posix_memalign(((void **)&chunk->userspace_addr), ELKVM_PAGESIZE, chunk->memory_size);
  assert(err == 0);
  err = ioctl(get_vmfd(), KVM_SET_USER_MEMORY_REGION, chunk.get());
  assert(err == 0);
  return 0;
}

void elkvm_emulate_vmcall(const std::shared_ptr<Elkvm::VCPU>& vcpu) {
  /* INTEL VMCALL instruction is three bytes long */
  CURRENT_ABI::paramtype rip = vcpu->get_reg(Elkvm::Reg_t::rip);
  vcpu->set_reg(Elkvm::Reg_t::rip, rip += 3);
}

int elkvm_dump_valid_msrs(Elkvm::elkvm_opts *opts) {
  struct kvm_msr_list *list = reinterpret_cast<struct kvm_msr_list *>(
      malloc( sizeof(struct kvm_msr_list) + 255 * sizeof(uint32_t)));
  list->nmsrs = 255;

  int err = ioctl(opts->fd, KVM_GET_MSR_INDEX_LIST, list);
  if(err < 0) {
    free(list);
    return -errno;
  }

  for(unsigned i = 0; i < list->nmsrs; i++) {
    printf("MSR: 0x%x\n", list->indices[i]);
  }
  free(list);

  return 0;
}

