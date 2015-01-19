#include <string>

#include <errno.h>
#include <iostream>
#include <iomanip>
#include <cstdbool>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <stropts.h>
#include <unistd.h>

#include <elkvm/debug.h>
#include <elkvm/elkvm.h>
#include <elkvm/elkvm-log.h>
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

namespace Elkvm {

  VCPU::VCPU(std::shared_ptr<Elkvm::RegionManager> rm,
          int vmfd,
          unsigned cpu_num) :
	  is_singlestepping(false),
      _kvm_vcpu(vmfd, cpu_num),
      stack(rm) {
    initialize_regs();
    init_rsp();
  }

int VCPU::handle_stack_expansion(uint32_t err __attribute__((unused)),
    bool debug __attribute__((unused))) {
  stack.expand();
  return 1;
}

void VCPU::set_entry_point(guestptr_t rip) {
  set_reg(Elkvm::Reg_t::rip, rip);
  set_regs();
}

int VCPU::get_regs() {
  return _kvm_vcpu.get_regs();
}

int VCPU::get_sregs() {
  return _kvm_vcpu.get_sregs();
}

int VCPU::set_regs() {
  return _kvm_vcpu.set_regs();
}

int VCPU::set_sregs() {
  return _kvm_vcpu.set_sregs();
}

CURRENT_ABI::paramtype VCPU::get_reg(Elkvm::Reg_t reg) const {
  return _kvm_vcpu.get_reg(reg);
}

void VCPU::set_reg(Elkvm::Reg_t reg, CURRENT_ABI::paramtype val) {
  _kvm_vcpu.set_reg(reg, val);
}

CURRENT_ABI::paramtype VCPU::get_interrupt_bitmap(unsigned idx) const {
  return _kvm_vcpu.get_interrupt_bitmap(idx);
}

CURRENT_ABI::paramtype VCPU::get_msr(uint32_t idx) {
  return _kvm_vcpu.get_msr(idx);
}

void VCPU::set_msr(uint32_t idx, CURRENT_ABI::paramtype data) {
  _kvm_vcpu.set_msr(idx, data);
}

Segment VCPU::get_reg(Elkvm::Seg_t segtype) const {
  return _kvm_vcpu.get_reg(segtype);
}

void VCPU::set_reg(Elkvm::Seg_t segtype, const Elkvm::Segment &seg) {
  _kvm_vcpu.set_reg(segtype, seg);
}

void VCPU::initialize_regs() {
  //vcpu->regs.rsp = LINUX_64_STACK_BASE;
  /* for some reason this needs to be set */
  _kvm_vcpu.set_reg(Elkvm::Reg_t::rflags, 0x2);

  _kvm_vcpu.set_reg(Elkvm::Reg_t::cr0, VCPU_CR0_FLAG_PAGING
                                     | VCPU_CR0_FLAG_CACHE_DISABLE
                                     | VCPU_CR0_FLAG_NOT_WRITE_THROUGH
                                     | VCPU_CR0_FLAG_PROTECTED);

  _kvm_vcpu.set_reg(Elkvm::Reg_t::cr2, 0x0);
  _kvm_vcpu.set_reg(Elkvm::Reg_t::cr3, 0x0);

  _kvm_vcpu.set_reg(Elkvm::Reg_t::cr4, VCPU_CR4_FLAG_OSFXSR | VCPU_CR4_FLAG_PAE);

  _kvm_vcpu.set_reg(Elkvm::Reg_t::cr8, 0x0);

  _kvm_vcpu.set_reg(Elkvm::Reg_t::efer, VCPU_EFER_FLAG_NXE
                                      | VCPU_EFER_FLAG_LME
                                      | VCPU_EFER_FLAG_SCE);

  //TODO find out why this is!
  _kvm_vcpu.set_reg(Elkvm::Reg_t::apic_base, 0xfee00900);

  Segment cs(0x13, 0x0, 0xFFFFFFFF, 0xb, 0x1, 0x3, 0x0, 0x1, 0x1, 0x1, 0x0);
  _kvm_vcpu.set_reg(Elkvm::Seg_t::cs, cs);

  Segment ds(0x18, 0x0, 0xFFFFFFF, 0x3, 0x1, 0x0, 0x0, 0x1, 0x1, 0x1, 0x0);
  _kvm_vcpu.set_reg(Elkvm::Seg_t::ds, ds);

  Segment es(0x0, 0x0, 0xFFFFF, 0x3, 0x1, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0);
  _kvm_vcpu.set_reg(Elkvm::Seg_t::es, es);

  Segment fs(0x0, 0x0, 0xFFFFF, 0x3, 0x1, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0);
  _kvm_vcpu.set_reg(Elkvm::Seg_t::fs, fs);

  Segment gs(0x0, 0x10000, 0xFFFFF, 0x3, 0x1, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0);
  _kvm_vcpu.set_reg(Elkvm::Seg_t::gs, gs);

  Segment tr(0x0, 0x0, 0xFFFF, 0xb, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0);
  _kvm_vcpu.set_reg(Elkvm::Seg_t::tr, tr);

  Segment ldt(0x0, 0x0, 0xFFFF, 0x2, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0);
  _kvm_vcpu.set_reg(Elkvm::Seg_t::ldt, ldt);

  Segment ss(0xb, 0x0, 0xFFFFFFFF, 0x3, 0x1, 0x3, 0x0, 0x1, 0x1, 0x1, 0x0);
  _kvm_vcpu.set_reg(Elkvm::Seg_t::ss, ss);
}

CURRENT_ABI::paramtype VCPU::pop() {
  CURRENT_ABI::paramtype rsp = _kvm_vcpu.get_reg(Elkvm::Reg_t::rsp);
  CURRENT_ABI::paramtype val = stack.popq(rsp);
  rsp += 0x8;
  _kvm_vcpu.set_reg(Elkvm::Reg_t::rsp, rsp);
  return val;
}

void VCPU::push(CURRENT_ABI::paramtype val) {
  CURRENT_ABI::paramtype rsp = _kvm_vcpu.get_reg(Elkvm::Reg_t::rsp);
  rsp -= 0x8;
  _kvm_vcpu.set_reg(Elkvm::Reg_t::rsp, rsp);
  stack.pushq(rsp, val);
}

void VCPU::init_rsp() {
  _kvm_vcpu.set_reg(Elkvm::Reg_t::rsp, stack.user_base());
}

int VCPU::run() {
  return _kvm_vcpu.run();
}

void VCPU::print_info(const VM &vm) {
  if(exit_reason() == KVM_EXIT_MMIO
  || exit_reason() == KVM_EXIT_SHUTDOWN) {
    print(std::cerr, *this);
    print_stack(std::cerr, vm, *this);
    print_code(std::cerr, vm, *this);
  } else if(is_singlestepping && exit_reason() == hypercall_exit) {
    DBG() << "KVM_EXIT_HYPERCALL";
    print(std::cerr, *this);
    print_code(std::cerr, vm, *this);
  }
}

bool VCPU::handle_vm_exit() {
  switch(_kvm_vcpu.exit_reason()) {
    case KVM_EXIT_UNKNOWN:
        ERROR() << "KVM exit for unknown reason (KVM_EXIT_UNKNOWN)\n"
                << " Hardware exit reason: " << std::dec
                << _kvm_vcpu.exit_reason() << std::endl;
        return false;
    case KVM_EXIT_FAIL_ENTRY: {
      uint64_t code = hardware_entry_failure_reason();
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
      return false;
                              }
    case KVM_EXIT_EXCEPTION:
      fprintf(stderr, "KVM VCPU had exception\n");
      return false;
    case KVM_EXIT_SHUTDOWN:
      fprintf(stderr, "KVM VCPU did shutdown\n");
      get_regs();
      get_sregs();
      return false;
    case KVM_EXIT_DEBUG: {
      /* NO-OP */
      assert(false && "TODO make debugging api work!");
      /* XXX rethink debug handling */
//      int debug_handled = elkvm_handle_debug(vmi);
//      if(debug_handled == 0) {
      //}
      return false;
    }
    case KVM_EXIT_MMIO:
      fprintf(stderr, "KVM_EXIT_MMIO\n");
      print_mmio(std::cerr);
      return false;
    case KVM_EXIT_WATCHDOG:
      fprintf(stderr, "KVM_EXIT_WATCHDOG\n");
      return false;
    default:
      fprintf(stderr, "KVM VCPU exit for unknown reason: %i\n",
          exit_reason());
      return false;
  }
}

uint32_t VCPU::exit_reason() {
  return _kvm_vcpu.exit_reason();
}

uint64_t VCPU::hardware_exit_reason() {
  return _kvm_vcpu.hardware_exit_reason();
}

uint64_t VCPU::hardware_entry_failure_reason() {
  return _kvm_vcpu.hardware_entry_failure_reason();
}

std::ostream &VCPU::print_mmio(std::ostream &os) {
  return _kvm_vcpu.print_mmio(os);
}

std::ostream &print_stack(std::ostream &os, const VM &vm, const VCPU &vcpu) {
  assert(vcpu.get_reg(Elkvm::Reg_t::rsp) != 0x0);
  os << "\n Stack:\n";
  os <<   " ------\n";
  print_memory(os, vm, vcpu.get_reg(Elkvm::Reg_t::rsp), 16);
  return os;
}

std::ostream &print(std::ostream &os, const VCPU &vcpu) {
  os << std::endl << " Registers:" << std::endl;
  os << " ----------\n";

  os << PRINT_REGISTER("rip", vcpu.get_reg(Elkvm::Reg_t::rip))
            << PRINT_REGISTER("  rsp", vcpu.get_reg(Elkvm::Reg_t::rsp))
            << PRINT_REGISTER("  flags", vcpu.get_reg(Elkvm::Reg_t::rflags))
            << std::endl;

  print_flags(vcpu.get_reg(Elkvm::Reg_t::rflags));

  os << PRINT_REGISTER("rax", vcpu.get_reg(Elkvm::Reg_t::rax))
            << PRINT_REGISTER("  rbx", vcpu.get_reg(Elkvm::Reg_t::rbx))
            << PRINT_REGISTER("  rcx", vcpu.get_reg(Elkvm::Reg_t::rcx))
            << std::endl;

  os << PRINT_REGISTER("rdx", vcpu.get_reg(Elkvm::Reg_t::rdx))
            << PRINT_REGISTER("  rsi", vcpu.get_reg(Elkvm::Reg_t::rsi))
            << PRINT_REGISTER("  rdi", vcpu.get_reg(Elkvm::Reg_t::rdi))
            << std::endl;

  os << PRINT_REGISTER("rbp", vcpu.get_reg(Elkvm::Reg_t::rbp))
            << PRINT_REGISTER("   r8", vcpu.get_reg(Elkvm::Reg_t::r8))
            << PRINT_REGISTER("   r9", vcpu.get_reg(Elkvm::Reg_t::r9))
            << std::endl;

  os << PRINT_REGISTER("r10", vcpu.get_reg(Elkvm::Reg_t::r10))
            << PRINT_REGISTER("  r11", vcpu.get_reg(Elkvm::Reg_t::r11))
            << PRINT_REGISTER("  r12", vcpu.get_reg(Elkvm::Reg_t::r12))
            << std::endl;

  os << PRINT_REGISTER("r13", vcpu.get_reg(Elkvm::Reg_t::r13))
            << PRINT_REGISTER("  r14", vcpu.get_reg(Elkvm::Reg_t::r14))
            << PRINT_REGISTER("  r15", vcpu.get_reg(Elkvm::Reg_t::r15))
            << std::endl;

  os << PRINT_REGISTER("cr0", vcpu.get_reg(Elkvm::Reg_t::cr0))
            << PRINT_REGISTER("  cr2", vcpu.get_reg(Elkvm::Reg_t::cr2))
            << PRINT_REGISTER("  cr3", vcpu.get_reg(Elkvm::Reg_t::cr3))
            << std::endl;

  os << PRINT_REGISTER("cr4", vcpu.get_reg(Elkvm::Reg_t::cr4))
            << PRINT_REGISTER("  cr8", vcpu.get_reg(Elkvm::Reg_t::cr8))
            << std::endl;

  os << "\n Segment registers:\n";
  os <<   " ------------------\n";
  os << " register  selector  base              limit     type  p dpl db s l g avl\n";

  print(os, "cs ", vcpu.get_reg(Elkvm::Seg_t::cs));
  print(os, "ss ", vcpu.get_reg(Elkvm::Seg_t::ss));
  print(os, "ds ", vcpu.get_reg(Elkvm::Seg_t::ds));
  print(os, "es ", vcpu.get_reg(Elkvm::Seg_t::es));
  print(os, "fs ", vcpu.get_reg(Elkvm::Seg_t::fs));
  print(os, "gs ", vcpu.get_reg(Elkvm::Seg_t::gs));
  print(os, "tr ", vcpu.get_reg(Elkvm::Seg_t::tr));
  print(os, "ldt", vcpu.get_reg(Elkvm::Seg_t::ldt));
  print(os, "gdt",  vcpu.get_reg(Elkvm::Seg_t::gdt));
  print(os, "idt",  vcpu.get_reg(Elkvm::Seg_t::idt));

  os << "\n APIC:\n";
  os <<   " -----\n";
  os << PRINT_REGISTER("efer", vcpu.get_reg(Elkvm::Reg_t::efer))
            << PRINT_REGISTER("  apic base", vcpu.get_reg(Elkvm::Reg_t::apic_base))
            << std::endl;

  os << "\n Interrupt bitmap:\n";
  os <<   " -----------------\n";
  for (int i = 0; i < (KVM_NR_INTERRUPTS + 63) / 64; i++)
    os << " " << std::setw(16) << std::setfill('0') << vcpu.get_interrupt_bitmap(i);
  os << std::endl;

  return os;
}

std::ostream &print(std::ostream &os, const std::string &name,
   const Elkvm::Segment &seg)
{
  os << " " << name
    << std::hex
    << "       " << std::setw(4) << std::setfill('0') << seg.get_selector()
    << "      "  << std::setw(16) << std::setfill('0') << seg.get_base()
    << "  "      << std::setw(8) << std::setfill('0') << seg.get_limit()
    << "  "      << std::setw(2) << std::setfill('0')
    << static_cast<unsigned>(seg.get_type())
    << "    " << static_cast<unsigned>(seg.is_present())
    << " "    << static_cast<unsigned>(seg.get_dpl())
    << "   "  << static_cast<unsigned>(seg.get_db())
    << "  "   << static_cast<unsigned>(seg.get_s())
    << " "    << static_cast<unsigned>(seg.get_l())
    << " "    << static_cast<unsigned>(seg.get_g())
    << " "    << static_cast<unsigned>(seg.get_avl()) << std::endl;
  return os;
}

std::ostream &print(std::ostream &os, const std::string &name,
    struct kvm_dtable dtable)
{
  os << " " << name
    << std::hex
    << "                 " << std::setw(16) << std::setfill('0') << dtable.base
    << "  " << std::setw(8) << std::setfill('0') << dtable.limit
    << std::endl;
  return os;
}

//namespace Elkvm
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

void kvm_vcpu_dump_msr(std::shared_ptr<Elkvm::VCPU> vcpu, uint32_t msr) {
  std::cerr << " MSR: 0x" << std::hex << msr << ": 0x" << vcpu->get_msr(msr)
            << std::endl;
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
