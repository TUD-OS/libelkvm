#pragma once

namespace Elkvm {

enum Reg_t {
  rax, rbx, rcx, rdx,
  rsi, rdi, rsp, rbp,
  r8, r9, r10, r11,
  r12, r13, r14, r15,
  rip, rflags,
  cr0, cr2, cr3, cr4, cr8,
  efer,
  apic_base
};

enum Seg_t {
  cs, ds, es, fs, gs, ss,
  tr, ldt,
  gdt, idt
};

  //namespace Elkvm
}
