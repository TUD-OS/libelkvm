#pragma once
#include <elkvm/config.h>
#include <elkvm/regs.h>
#include <elkvm/stack.h>
#include <elkvm/syscall.h>

#include <linux/kvm.h>

#include <cstdbool>
#include <cstdio>

#ifdef HAVE_LIBUDIS86
#include <udis86.h>
#endif

class VCPU {
  private:
    int fd;
    struct kvm_regs regs;
    /*
      Initialize a VCPU's registers according to mode
    */
    int initialize_regs();


  public:
  Elkvm::Stack stack;
#ifdef HAVE_LIBUDIS86
  ud_t ud_obj;
#endif
  struct kvm_sregs sregs;
  struct kvm_run *run_struct;
  int singlestep;
  struct kvm_guest_debug debug;

    VCPU(std::shared_ptr<Elkvm::RegionManager> rm, int vmfd, unsigned cpu_num);
    /*
     * Get VCPU registers
     */
    int get_regs();
    int get_sregs();

    /*
     * Set VCPU registers
     */
    int set_regs();
    int set_sregs();

    /*
     * get and set single registers
     */
    CURRENT_ABI::paramtype get_reg(Elkvm::Reg_t reg);
    void set_reg(Elkvm::Reg_t reg, CURRENT_ABI::paramtype val);
    void set_entry_point(guestptr_t rip);

    /* MSRs */
    void set_msr(uint32_t idx, CURRENT_ABI::paramtype data);
    CURRENT_ABI::paramtype get_msr(uint32_t idx);

    /* RUNNING the VCPU */
    int run();

    /* get VCPU hypervisor exit reasons */
    uint32_t exit_reason();
    uint64_t hardware_exit_reason();
    uint64_t hardware_entry_failure_reason();

    /* Debugging */
    int set_debug();
    std::ostream &print_mmio(std::ostream &os);

  uint64_t pop() { uint64_t val = stack.popq(regs.rsp); regs.rsp += 0x8; return val; }
  void push(uint64_t val) { regs.rsp -= 0x8; stack.pushq(regs.rsp, val); }
  guestptr_t kernel_stack_base() { return stack.kernel_base(); }
  int handle_stack_expansion(uint32_t err, bool debug);
  void init_rsp() { regs.rsp = stack.user_base(); }
};

std::ostream &print(std::ostream &os, std::shared_ptr<VCPU> vcpu);
std::ostream &print(std::ostream &os, const std::string &name,
    struct kvm_segment seg);
std::ostream &print(std::ostream &os, const std::string &name,
    struct kvm_dtable dtable);

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

void kvm_vcpu_dump_msr(std::shared_ptr<VCPU> vcpu, uint32_t);

/*
 * \brief Returns true if the host supports vmx
*/
bool host_supports_vmx(void);

/*
 * \brief Get the host CPUID
*/
void host_cpuid(uint32_t, uint32_t, uint32_t *, uint32_t *, uint32_t *, uint32_t *);

void kvm_vcpu_dump_code(std::shared_ptr<VCPU> vcpu);
void kvm_vcpu_dump_code_at(std::shared_ptr<VCPU> vcpu, uint64_t guest_addr);

#ifdef HAVE_LIBUDIS86
/*
 * \brief Get the next byte of code to be executed.
 * This is mainly here for libudis86 disassembly
 */
int kvm_vcpu_get_next_code_byte(std::shared_ptr<VCPU> vcpu, uint64_t guest_addr);

void elkvm_init_udis86(std::shared_ptr<VCPU> vcpu, int mode);
#endif

void print_flags(uint64_t flags);
