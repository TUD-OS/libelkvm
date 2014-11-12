#pragma once

#include <elkvm/config.h>
#include <elkvm/kvm.h>
#include <elkvm/regs.h>
#include <elkvm/stack.h>
#include <elkvm/syscall.h>

#include <linux/kvm.h>

#include <cstdbool>
#include <cstdio>

#ifdef HAVE_LIBUDIS86
#include <udis86.h>
#endif

namespace Elkvm {

class Segment {
  CURRENT_ABI::paramtype _selector;
  CURRENT_ABI::paramtype _base;
  CURRENT_ABI::paramtype _limit;
  CURRENT_ABI::paramtype _type;
  CURRENT_ABI::paramtype _present;
  CURRENT_ABI::paramtype _dpl;
  CURRENT_ABI::paramtype _db;
  CURRENT_ABI::paramtype _s;
  CURRENT_ABI::paramtype _l;
  CURRENT_ABI::paramtype _g;
  CURRENT_ABI::paramtype _avl;

  public:
    Segment(CURRENT_ABI::paramtype base,
            CURRENT_ABI::paramtype limit) :
      _base(base),
      _limit(limit) {}

    Segment(CURRENT_ABI::paramtype selector,
            CURRENT_ABI::paramtype base,
            CURRENT_ABI::paramtype limit,
            CURRENT_ABI::paramtype type,
            CURRENT_ABI::paramtype present,
            CURRENT_ABI::paramtype dpl,
            CURRENT_ABI::paramtype db,
            CURRENT_ABI::paramtype s,
            CURRENT_ABI::paramtype l,
            CURRENT_ABI::paramtype g,
            CURRENT_ABI::paramtype avl) :
      _selector(selector),
      _base(base),
      _limit(limit),
      _type(type),
      _present(present),
      _dpl(dpl),
      _db(db),
      _s(s),
      _l(l),
      _g(g),
      _avl(avl) {}

    CURRENT_ABI::paramtype get_selector() const { return _selector; }
    CURRENT_ABI::paramtype get_base() const { return _base; }
    CURRENT_ABI::paramtype get_limit() const { return _limit; }
    CURRENT_ABI::paramtype get_type() const { return _type; }
    CURRENT_ABI::paramtype is_present() const { return _present; }
    CURRENT_ABI::paramtype get_dpl() const { return _dpl; }
    CURRENT_ABI::paramtype get_db() const { return _db; }
    CURRENT_ABI::paramtype get_s() const { return _s; }
    CURRENT_ABI::paramtype get_l() const { return _l; }
    CURRENT_ABI::paramtype get_g() const { return _g; }
    CURRENT_ABI::paramtype get_avl() const { return _avl; }

    void set_base(CURRENT_ABI::paramtype base) {
      _base = base;
    }
};

class VCPU {
  private:
    bool is_singlestepping;
    KVM::VCPU _kvm_vcpu;
    Elkvm::Stack stack;

    void initialize_regs();

  public:
    static const int hypercall_exit = 1;
#ifdef HAVE_LIBUDIS86
  ud_t ud_obj;
#endif

    VCPU(std::shared_ptr<Elkvm::RegionManager> rm, int vmfd, unsigned cpu_num);
    /*
     * Get VCPU registers from hypervisor
     */
    int get_regs();
    int get_sregs();

    /*
     * Set VCPU registers with hypervisor
     */
    int set_regs();
    int set_sregs();

    /*
     * get and set single registers
     */
    CURRENT_ABI::paramtype get_reg(Elkvm::Reg_t reg) const;
    Elkvm::Segment get_reg(Elkvm::Seg_t seg) const;
    CURRENT_ABI::paramtype get_interrupt_bitmap(unsigned idx) const;
    void set_reg(Elkvm::Reg_t reg, CURRENT_ABI::paramtype val);
    void set_reg(Elkvm::Seg_t seg, const Elkvm::Segment &s);
    void set_entry_point(guestptr_t rip);

    /* MSRs */
    void set_msr(uint32_t idx, CURRENT_ABI::paramtype data);
    CURRENT_ABI::paramtype get_msr(uint32_t idx);

    /* RUNNING the VCPU */
    int run();
    bool handle_vm_exit();

    /* get VCPU hypervisor exit reasons */
    uint32_t exit_reason();
    uint64_t hardware_exit_reason();
    uint64_t hardware_entry_failure_reason();

    /* Debugging */
    int enable_debug();
    int enable_software_breakpoints();
    bool is_singlestep() { return is_singlestepping; }
    int singlestep();
    int singlestep_off();
    std::ostream &print_mmio(std::ostream &os);

    void print_info();
    /* stack handling */
    CURRENT_ABI::paramtype pop();
    void push(CURRENT_ABI::paramtype val);
    guestptr_t kernel_stack_base() { return stack.kernel_base(); }
    int handle_stack_expansion(uint32_t err, bool debug);
    void init_rsp();
};

std::ostream &print(std::ostream &os, const VCPU &vcpu);
std::ostream &print(std::ostream &os, const std::string &name,
    const Elkvm::Segment &seg);
std::ostream &print(std::ostream &os, const std::string &name,
    struct kvm_dtable dtable);
std::ostream &print_stack(std::ostream &os, const VCPU &vcpu);

//namespace Elkvm
}

#define VCPU_CR0_FLAG_PAGING            0x80000000
#define VCPU_CR0_FLAG_CACHE_DISABLE     0x40000000
#define VCPU_CR0_FLAG_NOT_WRITE_THROUGH 0x20000000
#define VCPU_CR0_FLAG_PROTECTED         0x1

#define VCPU_CR4_FLAG_OSXSAVE 0x40000
#define VCPU_CR4_FLAG_OSFXSR  0x200
#define VCPU_CR4_FLAG_PAE     0x20
#define VCPU_CR4_FLAG_DE      0x8

#define VCPU_EFER_FLAG_SCE 0x1
#define VCPU_EFER_FLAG_LME 0x100
#define VCPU_EFER_FLAG_LMA 0x400
#define VCPU_EFER_FLAG_NXE 0x800
#define VMX_INVALID_GUEST_STATE 0x80000021
#define CPUID_EXT_VMX      (1 << 5)

#define VCPU_MSR_STAR   0xC0000081
#define VCPU_MSR_LSTAR  0xC0000082
#define VCPU_MSR_CSTAR  0xC0000083
#define VCPU_MSR_SFMASK 0XC0000084

void kvm_vcpu_dump_msr(std::shared_ptr<Elkvm::VCPU> vcpu, uint32_t);

/*
 * \brief Returns true if the host supports vmx
*/
bool host_supports_vmx(void);

/*
 * \brief Get the host CPUID
*/
void host_cpuid(uint32_t, uint32_t, uint32_t *, uint32_t *, uint32_t *, uint32_t *);

void kvm_vcpu_dump_code(std::shared_ptr<Elkvm::VCPU> vcpu);
void kvm_vcpu_dump_code_at(std::shared_ptr<Elkvm::VCPU> vcpu, uint64_t guest_addr);

#ifdef HAVE_LIBUDIS86
/*
 * \brief Get the next byte of code to be executed.
 * This is mainly here for libudis86 disassembly
 */
int kvm_vcpu_get_next_code_byte(std::shared_ptr<Elkvm::VCPU> vcpu, uint64_t guest_addr);

void elkvm_init_udis86(std::shared_ptr<Elkvm::VCPU> vcpu, int mode);
#endif

void print_flags(uint64_t flags);
