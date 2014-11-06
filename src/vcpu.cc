#include <string>

#include <errno.h>
#include <iostream>
#include <iomanip>
#include <cstdbool>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <stropts.h>
#include <sys/mman.h>
#include <unistd.h>

#include <elkvm/debug.h>
#include <elkvm/elkvm.h>
#include <elkvm/elkvm-internal.h>
#include <elkvm/gdt.h>
#include <elkvm/idt.h>
#include <elkvm/region.h>
#include <elkvm/regs.h>
#include <elkvm/stack.h>
#include <elkvm/syscall.h>
#include <elkvm/vcpu.h>

#define PRINT_REGISTER(name, reg) " " << name << ": " << std::hex << std::setw(16) \
  << std::setfill('0') << reg

  VCPU::VCPU(std::shared_ptr<Elkvm::RegionManager> rm,
          int vmfd,
          unsigned cpu_num) :
      stack(rm) {

    memset(&regs, 0, sizeof(struct kvm_regs));
    memset(&sregs, 0, sizeof(struct kvm_sregs));
    singlestep = 0;

    fd = ioctl(vmfd, KVM_CREATE_VCPU, cpu_num);
    assert(fd > 0 && "error creating vcpu");

    int err = initialize_regs();
    assert(err == 0 && "error initializing vcpu registers");

    init_rsp();

    run_struct = reinterpret_cast<struct kvm_run *>(
        mmap(NULL, sizeof(struct kvm_run), PROT_READ | PROT_WRITE,
        MAP_SHARED, fd, 0));
    assert(run_struct != nullptr && "error allocating run_struct");

//#ifdef HAVE_LIBUDIS86
//    elkvm_init_udis86(vcpu, mode);
//#endif
  }

int VCPU::handle_stack_expansion(uint32_t err __attribute__((unused)),
    bool debug __attribute__((unused))) {
  stack.expand();
  return 1;
}

int kvm_vcpu_set_rip(std::shared_ptr<VCPU>  vcpu, uint64_t rip) {
  int err = vcpu->get_regs();
  if(err) {
    return err;
  }

  vcpu->set_reg(Elkvm::Reg_t::rip, rip);

  err = vcpu->set_regs();
  if(err) {
    return err;
  }

  return 0;
}

int kvm_vcpu_set_cr3(std::shared_ptr<VCPU> vcpu, uint64_t cr3) {
  assert(vcpu != NULL);

  int err = vcpu->get_sregs();
  if(err) {
    return err;
  }

  vcpu->sregs.cr3 = cr3;

  err = vcpu->set_sregs();
  if(err) {
    return err;
  }

  return 0;
}

int VCPU::get_regs() {
  int err = ioctl(fd, KVM_GET_REGS, &regs);
  if(err) {
    return -errno;
  }

  return 0;
}

int VCPU::get_sregs() {
  int err = ioctl(fd, KVM_GET_SREGS, &sregs);
  if(err) {
    return -errno;
  }

  return 0;
}

int VCPU::set_regs() {
  int err = ioctl(fd, KVM_SET_REGS, &regs);
  if(err) {
    return -errno;
  }

  return 0;
}

int VCPU::set_sregs() {
  int err = ioctl(fd, KVM_SET_SREGS, &sregs);
  if(err) {
    return -errno;
  }

  return 0;
}

CURRENT_ABI::paramtype VCPU::get_reg(Elkvm::Reg_t reg) {
  switch(reg) {
    case Elkvm::Reg_t::rax:
      return regs.rax;
    case Elkvm::Reg_t::rbx:
      return regs.rbx;
    case Elkvm::Reg_t::rcx:
      return regs.rcx;
    case Elkvm::Reg_t::rdx:
      return regs.rdx;
    case Elkvm::Reg_t::rsi:
      return regs.rsi;
    case Elkvm::Reg_t::rdi:
      return regs.rdi;
    case Elkvm::Reg_t::rsp:
      return regs.rsp;
    case Elkvm::Reg_t::rbp:
      return regs.rbp;
    case Elkvm::Reg_t::r8:
      return regs.r8;
    case Elkvm::Reg_t::r9:
      return regs.r9;
    case Elkvm::Reg_t::r10:
      return regs.r10;
    case Elkvm::Reg_t::r11:
      return regs.r11;
    case Elkvm::Reg_t::r12:
      return regs.r12;
    case Elkvm::Reg_t::r13:
      return regs.r13;
    case Elkvm::Reg_t::r14:
      return regs.r14;
    case Elkvm::Reg_t::r15:
      return regs.r15;
    case Elkvm::Reg_t::rip:
      return regs.rip;
    case Elkvm::Reg_t::rflags:
      return regs.rflags;
    case Elkvm::Reg_t::cr0:
      return sregs.cr0;
    case Elkvm::Reg_t::cr2:
      return sregs.cr2;
    case Elkvm::Reg_t::cr3:
      return sregs.cr3;
    case Elkvm::Reg_t::cr4:
      return sregs.cr4;
    case Elkvm::Reg_t::cr8:
      return sregs.cr8;
    case Elkvm::Reg_t::efer:
      return sregs.efer;
    case Elkvm::Reg_t::apic_base:
      return sregs.apic_base;

    default:
      assert(false);
      return -1;
  }
}

void VCPU::set_reg(Elkvm::Reg_t reg, CURRENT_ABI::paramtype val) {
  switch(reg) {
    case Elkvm::Reg_t::rax:
      regs.rax = val;
      break;
    case Elkvm::Reg_t::rbx:
      regs.rbx = val;
      break;
    case Elkvm::Reg_t::rcx:
      regs.rcx = val;
      break;
    case Elkvm::Reg_t::rdx:
      regs.rdx = val;
      break;
    case Elkvm::Reg_t::rsi:
      regs.rsi = val;
      break;
    case Elkvm::Reg_t::rdi:
      regs.rdi = val;
      break;
    case Elkvm::Reg_t::rsp:
      regs.rsp = val;
      break;
    case Elkvm::Reg_t::rbp:
      regs.rbp = val;
      break;
    case Elkvm::Reg_t::r8:
      regs.r8 = val;
      break;
    case Elkvm::Reg_t::r9:
      regs.r9 = val;
      break;
    case Elkvm::Reg_t::r10:
      regs.r10 = val;
      break;
    case Elkvm::Reg_t::r11:
      regs.r11 = val;
      break;
    case Elkvm::Reg_t::r12:
      regs.r12 = val;
      break;
    case Elkvm::Reg_t::r13:
      regs.r13 = val;
      break;
    case Elkvm::Reg_t::r14:
      regs.r14 = val;
      break;
    case Elkvm::Reg_t::r15:
      regs.r15 = val;
      break;
    case Elkvm::Reg_t::rip:
      regs.rip = val;
      break;
    case Elkvm::Reg_t::rflags:
      regs.rflags = val;
      break;
    case Elkvm::Reg_t::cr0:
      sregs.cr0 = val;
      break;
    case Elkvm::Reg_t::cr2:
      sregs.cr2 = val;
      break;
    case Elkvm::Reg_t::cr3:
      sregs.cr3 = val;
      break;
    case Elkvm::Reg_t::cr4:
      sregs.cr4 = val;
      break;
    case Elkvm::Reg_t::cr8:
      sregs.cr8 = val;
      break;
    case Elkvm::Reg_t::efer:
      sregs.efer = val;
      break;
    case Elkvm::Reg_t::apic_base:
      sregs.apic_base = val;
      break;

    default:
      assert(false);
  }
}
int kvm_vcpu_get_msr(std::shared_ptr<VCPU> vcpu, uint32_t index, uint64_t *res_p) {
  struct kvm_msrs *msr = reinterpret_cast<struct kvm_msrs *>(
      malloc(sizeof(struct kvm_msrs) + sizeof(struct kvm_msr_entry)));
  msr->nmsrs = 1;
  msr->entries[0].index = index;

  int err = ioctl(vcpu->fd, KVM_GET_MSRS, msr);
  if(err < 0) {
    *res_p = -1;
    free(msr);
    return -errno;
  }

  *res_p = msr->entries[0].data;
  free(msr);
  return 0;
}

int kvm_vcpu_set_msr(std::shared_ptr<VCPU> vcpu, uint32_t index, uint64_t data) {
  struct kvm_msrs *msr = reinterpret_cast<struct kvm_msrs *>(
      malloc(sizeof(struct kvm_msrs) + sizeof(struct kvm_msr_entry)));
  memset(msr, 0, sizeof(struct kvm_msrs) + sizeof(struct kvm_msr_entry));

  msr->nmsrs = 1;
  msr->entries[0].index = index;
  msr->entries[0].data  = data;

  int err = ioctl(vcpu->fd, KVM_SET_MSRS, msr);
  free(msr);
  if(err < 0) {
    return -errno;
  }

  return 0;
}

int VCPU::initialize_regs() {

  memset(&regs, 0, sizeof(struct kvm_regs));
  //vcpu->regs.rsp = LINUX_64_STACK_BASE;
  /* for some reason this needs to be set */
  regs.rflags = 0x00000002;

//  int err = vcpu->set_regs();
//  if(err) {
//    return err;
//  }

  sregs.cr0 = VCPU_CR0_FLAG_PAGING | VCPU_CR0_FLAG_CACHE_DISABLE |
      VCPU_CR0_FLAG_NOT_WRITE_THROUGH |
      VCPU_CR0_FLAG_PROTECTED;
  sregs.cr4 = VCPU_CR4_FLAG_OSFXSR | VCPU_CR4_FLAG_PAE;
  sregs.cr2 = sregs.cr3 = sregs.cr8 = 0x0;
  sregs.efer = VCPU_EFER_FLAG_NXE | VCPU_EFER_FLAG_LME | VCPU_EFER_FLAG_SCE;

  //TODO find out why this is!
  sregs.apic_base = 0xfee00900;

  sregs.cs.selector = 0x0013;
  sregs.cs.base     = 0x0;
  sregs.cs.limit    = 0xFFFFFFFF;
  sregs.cs.type     = 0xb;
  sregs.cs.present  = 0x1;
  sregs.cs.dpl      = 0x3;
  sregs.cs.db       = 0x0;
  sregs.cs.s        = 0x1;
  sregs.cs.l        = 0x1;
  sregs.cs.g        = 0x1;
  sregs.cs.avl      = 0x0;

  sregs.ds.selector = 0x0018;
  sregs.ds.base     = 0x0;
  sregs.ds.limit    = 0xFFFFFFFF;
  sregs.ds.type     = 0x3;
  sregs.ds.present  = 0x1;
  sregs.ds.dpl      = 0x0;
  sregs.ds.db       = 0x0;
  sregs.ds.s        = 0x1;
  sregs.ds.l        = 0x1;
  sregs.ds.g        = 0x1;
  sregs.ds.avl      = 0x0;

  sregs.es.selector = 0x0;
  sregs.es.base     = 0x0;
  sregs.es.limit    = 0xFFFFF;
  sregs.es.type     = 0x3;
  sregs.es.present  = 0x1;
  sregs.es.dpl      = 0x0;
  sregs.es.db       = 0x0;
  sregs.es.s        = 0x1;
  sregs.es.l        = 0x0;
  sregs.es.g        = 0x0;
  sregs.es.avl      = 0x0;

  sregs.fs.selector = 0x0;
  sregs.fs.base     = 0x0;
  sregs.fs.limit    = 0xFFFFF;
  sregs.fs.type     = 0x3;
  sregs.fs.present  = 0x1;
  sregs.fs.dpl      = 0x0;
  sregs.fs.db       = 0x0;
  sregs.fs.s        = 0x1;
  sregs.fs.l        = 0x0;
  sregs.fs.g        = 0x0;
  sregs.fs.avl      = 0x0;

  sregs.gs.selector = 0x0;
  sregs.gs.base     = 0x10000;
  sregs.gs.limit    = 0xFFFFF;
  sregs.gs.type     = 0x3;
  sregs.gs.present  = 0x1;
  sregs.gs.dpl      = 0x0;
  sregs.gs.db       = 0x0;
  sregs.gs.s        = 0x1;
  sregs.gs.l        = 0x0;
  sregs.gs.g        = 0x0;
  sregs.gs.avl      = 0x0;

  sregs.tr.selector = 0x0;
  sregs.tr.base     = 0x0;
  sregs.tr.limit    = 0xFFFF;
  sregs.tr.type     = 0xb;
  sregs.tr.present  = 0x1;
  sregs.tr.dpl      = 0x0;
  sregs.tr.db       = 0x0;
  sregs.tr.s        = 0x0;
  sregs.tr.l        = 0x1;
  sregs.tr.g        = 0x0;
  sregs.tr.avl      = 0x0;

  sregs.ldt.selector = 0x0;
  sregs.ldt.base     = 0x0;
  sregs.ldt.limit    = 0xFFFF;
  sregs.ldt.type     = 0x2;
  sregs.ldt.present  = 0x1;
  sregs.ldt.dpl      = 0x0;
  sregs.ldt.db       = 0x0;
  sregs.ldt.s        = 0x0;
  sregs.ldt.l        = 0x0;
  sregs.ldt.g        = 0x0;
  sregs.ldt.avl      = 0x0;

  sregs.ss.selector = 0x000b;
  sregs.ss.base     = 0x0;
  sregs.ss.limit    = 0xFFFFFFFF;
  sregs.ss.type     = 0x3;
  sregs.ss.present  = 0x1;
  sregs.ss.dpl      = 0x3;
  sregs.ss.db       = 0x0;
  sregs.ss.s        = 0x1;
  sregs.ss.l        = 0x1;
  sregs.ss.g        = 0x1;
  sregs.ss.avl      = 0x0;

  /* gets set in elkvm_gdt_setup */
  sregs.gdt.base  = 0x0;
  sregs.gdt.limit = 0xFFFF;

  /* gets set in elkvm_idt_setup */
  sregs.idt.base  = 0xFBFF000;
  sregs.idt.limit = 0x0;


  //memset(&vcpu->sregs.es, 0, sizeof(struct kvm_segment));
  //memset(&vcpu->sregs.fs, 0, sizeof(struct kvm_segment));
  //memset(&vcpu->sregs.gs, 0, sizeof(struct kvm_segment));
  //memset(&vcpu->sregs.tr, 0, sizeof(struct kvm_segment));
  //memset(&vcpu->sregs.ldt, 0, sizeof(struct kvm_segment));

  //err = vcpu->set_sregs();
  return 0;
}

int kvm_vcpu_run(std::shared_ptr<VCPU> vcpu) {
  int err = ioctl(vcpu->fd, KVM_RUN, 0);
  if(err != 0) {
    if(errno == EINTR) {
      fprintf(stderr, "VM interrupted by signal\n");
      return -EINTR;
    } else if(errno != EAGAIN) {
      fprintf(stderr, "ERROR running VCPU No: %i Msg: %s\n", errno, strerror(errno));
      return -1;
    }
  }

  return 0;
}

int Elkvm::VM::run() {

  int is_running = 1;
//  if(vcpu->singlestep) {
//    elkvm_gdt_dump(vcpu->vm);
//    kvm_vcpu_dump_msr(vcpu, VCPU_MSR_STAR);
//    kvm_vcpu_dump_msr(vcpu, VCPU_MSR_LSTAR);
//    kvm_vcpu_dump_msr(vcpu, VCPU_MSR_CSTAR);
//    kvm_pager_dump_page_tables(&vcpu->vm->pager);
//  }

  std::shared_ptr<VCPU> vcpu = get_vcpu(0);
  int err = 0;
  while(is_running) {

    err = vcpu->set_regs();
    if(err) {
      return err;
    }
//    if(vcpu->singlestep) {
//      err = kvm_vcpu_singlestep(vcpu);
//      if(err) {
//        return err;
//      }
//    }

    err = kvm_vcpu_run(vcpu);
    if(err) {
      break;
    }

    err = vcpu->get_regs();
    if(err) {
      return err;
    }

    switch(vcpu->run_struct->exit_reason) {
      case KVM_EXIT_UNKNOWN:
        fprintf(stderr, "KVM exit for unknown reason (KVM_EXIT_UNKNOWN)\n");
        fprintf(stderr, "Hardware exit reason: %llu\n",
            vcpu->run_struct->hw.hardware_exit_reason);
        is_running = 0;
        break;
      case KVM_EXIT_HYPERCALL:
        if(vcpu->singlestep) {
          fprintf(stderr, "KVM_EXIT_HYPERCALL\n");
          kvm_vcpu_dump_regs(vcpu);
          kvm_vcpu_dump_code(vcpu);
        }
        err = handle_hypercall(vcpu);
        if(err == ELKVM_HYPERCALL_EXIT) {
          is_running = 0;
        } else if(err) {
          is_running = 0;
          fprintf(stderr, "ELKVM: Could not handle hypercall!\n");
          fprintf(stderr, "Errno: %i Msg: %s\n", err, strerror(err));
        }
        break;
      case KVM_EXIT_FAIL_ENTRY: {
        ;
        uint64_t code = vcpu->run_struct->fail_entry.hardware_entry_failure_reason;
        fprintf(stderr, "KVM: entry failed, hardware error 0x%lx\n",
          code);
        if (host_supports_vmx() && code == VMX_INVALID_GUEST_STATE) {
          fprintf(stderr,
            "\nIf you're running a guest on an Intel machine without "
                "unrestricted mode\n"
            "support, the failure can be most likely due to the guest "
                "entering an invalid\n"
            "state for Intel VT. For example, the guest maybe running "
                "in big real mode\n"
            "which is not supported on less recent Intel processors."
                "\n\n");
        }
        is_running = 0;
        break;
                                }
      case KVM_EXIT_EXCEPTION:
        fprintf(stderr, "KVM VCPU had exception\n");
        is_running = 0;
        break;
      case KVM_EXIT_SHUTDOWN:
        fprintf(stderr, "KVM VCPU did shutdown\n");
        is_running = 0;
        vcpu->get_regs();
        vcpu->get_sregs();
        break;
      case KVM_EXIT_DEBUG: {
        /* NO-OP */
        ;
        /* XXX rethink debug handling */
//        int debug_handled = elkvm_handle_debug(vmi);
//        if(debug_handled == 0) {
          is_running = 0;
        //}
        break;
      }
      case KVM_EXIT_MMIO:
        fprintf(stderr, "KVM_EXIT_MMIO\n");
        fprintf(stderr, "\tphys_addr: 0x%llx data[0] %x data[1] %x"
            " data[2] %x data[3] %x data[4] %x data[5] %x "
            " data[6] %x data[7] %x len 0x%x write %i\n",
            vcpu->run_struct->mmio.phys_addr,
            vcpu->run_struct->mmio.data[0],
            vcpu->run_struct->mmio.data[1],
            vcpu->run_struct->mmio.data[2],
            vcpu->run_struct->mmio.data[3],
            vcpu->run_struct->mmio.data[4],
            vcpu->run_struct->mmio.data[5],
            vcpu->run_struct->mmio.data[6],
            vcpu->run_struct->mmio.data[7],
            vcpu->run_struct->mmio.len,
            vcpu->run_struct->mmio.is_write);
        is_running = 0;
        break;
      case KVM_EXIT_WATCHDOG:
        fprintf(stderr, "KVM_EXIT_WATCHDOG\n");
        is_running = 0;
        break;
      default:
        fprintf(stderr, "KVM VCPU exit for unknown reason: %i\n",
            vcpu->run_struct->exit_reason);
        is_running = 0;
        break;
    }

    if(  vcpu->run_struct->exit_reason == KVM_EXIT_MMIO ||
        vcpu->run_struct->exit_reason == KVM_EXIT_SHUTDOWN) {
      kvm_vcpu_dump_regs(vcpu);
      dump_stack(vcpu);
      kvm_vcpu_dump_code(vcpu);
    }

  }
  return 0;
}

bool host_supports_vmx(void) {
    uint32_t ecx, unused;

    host_cpuid(1, 0, &unused, &unused, &ecx, &unused);
    return ecx & CPUID_EXT_VMX;
}

void host_cpuid(uint32_t function, uint32_t count,
                uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
    uint32_t vec[4];

#ifdef __x86_64__
    asm volatile("cpuid"
                 : "=a"(vec[0]), "=b"(vec[1]),
                   "=c"(vec[2]), "=d"(vec[3])
                 : "0"(function), "c"(count) : "cc");
#else
    asm volatile("pusha \n\t"
                 "cpuid \n\t"
                 "mov %%eax, 0(%2) \n\t"
                 "mov %%ebx, 4(%2) \n\t"
                 "mov %%ecx, 8(%2) \n\t"
                 "mov %%edx, 12(%2) \n\t"
                 "popa"
                 : : "a"(function), "c"(count), "S"(vec)
                 : "memory", "cc");
#endif

    if (eax)
        *eax = vec[0];
    if (ebx)
        *ebx = vec[1];
    if (ecx)
        *ecx = vec[2];
    if (edx)
        *edx = vec[3];
}

void kvm_vcpu_dump_msr(std::shared_ptr<VCPU> vcpu, uint32_t msr) {
  uint64_t r;
  int err = kvm_vcpu_get_msr(vcpu, msr, &r);
  if(err) {
    fprintf(stderr, "WARNING: Could not get MSR: 0x%x\n", msr);
    return;
  }

  fprintf(stderr, " MSR: 0x%x: 0x%016lx\n", msr, r);
}

void kvm_vcpu_dump_regs(std::shared_ptr<VCPU> vcpu) {
  std::cerr << std::endl << " Registers:" << std::endl;
  std::cerr << " ----------\n";

  std::cerr << PRINT_REGISTER("rip", vcpu->get_reg(Elkvm::Reg_t::rip))
            << PRINT_REGISTER("  rsp", vcpu->get_reg(Elkvm::Reg_t::rsp))
            << PRINT_REGISTER("  flags", vcpu->get_reg(Elkvm::Reg_t::rflags))
            << std::endl;

  print_flags(vcpu->get_reg(Elkvm::Reg_t::rflags));

  std::cerr << PRINT_REGISTER("rax", vcpu->get_reg(Elkvm::Reg_t::rax))
            << PRINT_REGISTER("  rbx", vcpu->get_reg(Elkvm::Reg_t::rbx))
            << PRINT_REGISTER("  rcx", vcpu->get_reg(Elkvm::Reg_t::rcx))
            << std::endl;

  std::cerr << PRINT_REGISTER("rdx", vcpu->get_reg(Elkvm::Reg_t::rdx))
            << PRINT_REGISTER("  rsi", vcpu->get_reg(Elkvm::Reg_t::rsi))
            << PRINT_REGISTER("  rdi", vcpu->get_reg(Elkvm::Reg_t::rdi))
            << std::endl;

  std::cerr << PRINT_REGISTER("rbp", vcpu->get_reg(Elkvm::Reg_t::rbp))
            << PRINT_REGISTER("   r8", vcpu->get_reg(Elkvm::Reg_t::r8))
            << PRINT_REGISTER("   r9", vcpu->get_reg(Elkvm::Reg_t::r9))
            << std::endl;

  std::cerr << PRINT_REGISTER("r10", vcpu->get_reg(Elkvm::Reg_t::r10))
            << PRINT_REGISTER("  r11", vcpu->get_reg(Elkvm::Reg_t::r11))
            << PRINT_REGISTER("  r12", vcpu->get_reg(Elkvm::Reg_t::r12))
            << std::endl;

  std::cerr << PRINT_REGISTER("r13", vcpu->get_reg(Elkvm::Reg_t::r13))
            << PRINT_REGISTER("  r14", vcpu->get_reg(Elkvm::Reg_t::r14))
            << PRINT_REGISTER("  r15", vcpu->get_reg(Elkvm::Reg_t::r15))
            << std::endl;

  std::cerr << PRINT_REGISTER("cr0", vcpu->sregs.cr0)
            << PRINT_REGISTER("  cr2", vcpu->sregs.cr2)
            << PRINT_REGISTER("  cr3", vcpu->sregs.cr3)
            << std::endl;

  std::cerr << PRINT_REGISTER("cr4", vcpu->sregs.cr4)
            << PRINT_REGISTER("  cr8", vcpu->sregs.cr8)
            << std::endl;

  std::cerr << "\n Segment registers:\n";
  std::cerr <<   " ------------------\n";
  std::cerr << " register  selector  base              limit     type  p dpl db s l g avl\n";

  print_segment("cs ", vcpu->sregs.cs);
  print_segment("ss ", vcpu->sregs.ss);
  print_segment("ds ", vcpu->sregs.ds);
  print_segment("es ", vcpu->sregs.es);
  print_segment("fs ", vcpu->sregs.fs);
  print_segment("gs ", vcpu->sregs.gs);
  print_segment("tr ", vcpu->sregs.tr);
  print_segment("ldt", vcpu->sregs.ldt);
  print_dtable("gdt",  vcpu->sregs.gdt);
  print_dtable("idt",  vcpu->sregs.idt);

  std::cerr << "\n APIC:\n";
  std::cerr <<   " -----\n";
  std::cerr << PRINT_REGISTER("efer", vcpu->sregs.efer)
            << PRINT_REGISTER("  apic base", vcpu->sregs.apic_base)
            << std::endl;

  std::cerr << "\n Interrupt bitmap:\n";
  std::cerr <<   " -----------------\n";
  for (int i = 0; i < (KVM_NR_INTERRUPTS + 63) / 64; i++)
    std::cerr << " " << std::setw(16) << std::setfill('0') << vcpu->sregs.interrupt_bitmap[i];
  std::cerr << std::endl;

  return;
}

void print_flags(uint64_t flags) {
  std::cerr << " [";
  std::cerr << (((flags >> 16) & 0x1) ? "RF " : "");
  std::cerr << (((flags >> 11) & 0x1) ? "OF " : "");
  std::cerr << (((flags >> 10) & 0x1) ? "DF " : "");
  std::cerr << (((flags >>  9) & 0x1) ? "IF " : "");
  std::cerr << (((flags >>  8) & 0x1) ? "TF " : "");
  std::cerr << (((flags >>  7) & 0x1) ? "SF " : "");
  std::cerr << (((flags >>  6) & 0x1) ? "ZF " : "");
  std::cerr << (((flags >>  4) & 0x1) ? "AF " : "");
  std::cerr << (((flags >>  2) & 0x1) ? "PF " : "");
  std::cerr << (((flags) & 0x1) ? "CF" : "");
  std::cerr << "]\n";
}

void print_segment(const std::string name, struct kvm_segment seg)
{
  std::cerr << " " << name
    << std::hex
    << "       " << std::setw(4) << std::setfill('0') << seg.selector
    << "      "  << std::setw(16) << std::setfill('0') << seg.base
    << "  "      << std::setw(8) << std::setfill('0') << seg.limit
    << "  "      << std::setw(2) << std::setfill('0') << static_cast<unsigned>(seg.type)
    << "    " << static_cast<unsigned>(seg.present)
    << " "    << static_cast<unsigned>(seg.dpl)
    << "   "  << static_cast<unsigned>(seg.db)
    << "  "   << static_cast<unsigned>(seg.s)
    << " "    << static_cast<unsigned>(seg.l)
    << " "    << static_cast<unsigned>(seg.g)
    << " "    << static_cast<unsigned>(seg.avl) << std::endl;
}

void print_dtable(const std::string name, struct kvm_dtable dtable)
{
  std::cerr << " " << name
    << std::hex
    << "                 " << std::setw(16) << std::setfill('0') << dtable.base
    << "  " << std::setw(8) << std::setfill('0') << dtable.limit
    << std::endl;
}

void kvm_vcpu_dump_code_at(std::shared_ptr<VCPU> vcpu, uint64_t guest_addr) {
  (void)vcpu; (void)guest_addr;
#ifdef HAVE_LIBUDIS86
  int err = kvm_vcpu_get_next_code_byte(vcpu, guest_addr);
  if(err) {
    return;
  }

  fprintf(stderr, "\n Code:\n");
  fprintf(stderr,   " -----\n");
  while(ud_disassemble(&vcpu->ud_obj)) {
    fprintf(stderr, " %s\n", ud_insn_asm(&vcpu->ud_obj));
  }
  fprintf(stderr, "\n");
#else
  return;
#endif
}

void kvm_vcpu_dump_code(std::shared_ptr<VCPU> vcpu) {
  kvm_vcpu_dump_code_at(vcpu, vcpu->get_reg(Elkvm::Reg_t::rip));
}

#ifdef HAVE_LIBUDIS86
int kvm_vcpu_get_next_code_byte(std::shared_ptr<VCPU> vcpu, uint64_t guest_addr) {
//  assert(guest_addr != 0x0);
//  void *host_p = Elkvm::vmi->get_region_manager().get_pager().get_host_p(guest_addr);
//  assert(host_p != NULL);
//  size_t disassembly_size = 40;
//  ud_set_input_buffer(&vcpu->ud_obj, (const uint8_t *)host_p, disassembly_size);
//
//  return 0;
}

void elkvm_init_udis86(std::shared_ptr<VCPU> vcpu, int mode) {
  ud_init(&vcpu->ud_obj);
  switch(mode) {
    case VM_MODE_X86_64:
      ud_set_mode(&vcpu->ud_obj, 64);
  }
  ud_set_syntax(&vcpu->ud_obj, UD_SYN_INTEL);
}

#endif

int kvm_vcpu_had_page_fault(std::shared_ptr<VCPU> vcpu) {
  return vcpu->sregs.cr2 != 0x0;
}
