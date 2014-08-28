#pragma once
#include "config.h"

#include <linux/kvm.h>
#include <stdbool.h>
#include <stdio.h>
#ifdef HAVE_LIBUDIS86
#include <udis86.h>
#endif

#include <stack.h>

struct kvm_vcpu {
  int fd;
  Elkvm::Stack stack;
#ifdef HAVE_LIBUDIS86
  ud_t ud_obj;
#endif
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  struct kvm_run *run_struct;
  int singlestep;
  struct kvm_guest_debug debug;

  kvm_vcpu(std::shared_ptr<Elkvm::RegionManager> rm) : stack(rm) {}
  uint64_t pop() { uint64_t val = stack.popq(regs.rsp); regs.rsp += 0x8; return val; }
  void push(uint64_t val) { regs.rsp -= 0x8; stack.pushq(regs.rsp, val); }
  guestptr_t kernel_stack_base() { return stack.kernel_base(); }
  int check_pagefault(uint32_t err, bool debug) { (void)err; (void)debug; return 0; }
  void init_rsp() { regs.rsp = stack.user_base(); }
};

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

/*
  Set the VCPU's rip to a specific value
*/
int kvm_vcpu_set_rip(struct kvm_vcpu *, uint64_t);

/*
 * \brief Set the VCPU's CR3 to a specific value
 */
int kvm_vcpu_set_cr3(struct kvm_vcpu *, uint64_t);

/*
  Get the VCPU's registers
*/
int kvm_vcpu_get_regs(struct kvm_vcpu *);
int kvm_vcpu_get_sregs(struct kvm_vcpu *);

/*
  Set the VCPU's registers
*/
int kvm_vcpu_set_regs(struct kvm_vcpu *);
int kvm_vcpu_set_sregs(struct kvm_vcpu *);

int kvm_vcpu_get_msr(struct kvm_vcpu *, uint32_t, uint64_t *);
int kvm_vcpu_set_msr(struct kvm_vcpu *, uint32_t, uint64_t);
void kvm_vcpu_dump_msr(struct kvm_vcpu *, uint32_t);

/*
  Initialize a VCPU's registers according to mode
*/
int kvm_vcpu_initialize_regs(struct kvm_vcpu *, int);

/*
  Initialize the VCPU registers for long mode
*/
int kvm_vcpu_initialize_long_mode(struct kvm_vcpu *);

/*
 * \brief Run the VCPU
*/
int kvm_vcpu_run(struct kvm_vcpu *);

int kvm_vcpu_had_page_fault(struct kvm_vcpu *);

/*
 * \brief Returns true if the host supports vmx
*/
bool host_supports_vmx(void);

/*
 * \brief Get the host CPUID
*/
void host_cpuid(uint32_t, uint32_t, uint32_t *, uint32_t *, uint32_t *, uint32_t *);

void kvm_vcpu_dump_regs(struct kvm_vcpu *);

void kvm_vcpu_dump_code(struct kvm_vcpu *);
void kvm_vcpu_dump_code_at(struct kvm_vcpu *vcpu, uint64_t guest_addr);

#ifdef HAVE_LIBUDIS86
/*
 * \brief Get the next byte of code to be executed.
 * This is mainly here for libudis86 disassembly
 */
int kvm_vcpu_get_next_code_byte(struct kvm_vcpu *, uint64_t guest_addr);

void elkvm_idt_dump_isr(Elkvm::kvm_vm *, int);
void elkvm_init_udis86(struct kvm_vcpu *, int mode);
#endif

static inline
__attribute__((used))
void print_dtable(const char *name, struct kvm_dtable dtable)
{
  fprintf(stderr, " %s                 %016llx  %08hx\n",
          name, (uint64_t) dtable.base, (uint16_t) dtable.limit);
}

static inline
__attribute__((used))
void print_segment(const char *name, struct kvm_segment seg)
{
  fprintf(stderr, " %s       %04hx      %016llx  %08x  %02hhx    %x %x   %x  %x %x %x %x\n",
          name, (uint16_t) seg.selector, (uint64_t) seg.base, (uint32_t) seg.limit,
          (uint8_t) seg.type, seg.present, seg.dpl, seg.db, seg.s, seg.l,
          seg.g, seg.avl);
}
