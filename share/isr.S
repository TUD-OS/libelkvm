.macro interrupt_stub iv
.globl _interrupt_stub_\iv
_interrupt_stub_\iv:
  pushq $\iv
  pushq $2
  jmp _isr_common
.endm

// Exceptions
interrupt_stub 0
interrupt_stub 1
interrupt_stub 2
interrupt_stub 3
interrupt_stub 4
interrupt_stub 5
interrupt_stub 6
interrupt_stub 7
interrupt_stub 8
interrupt_stub 9
interrupt_stub 10
interrupt_stub 11
interrupt_stub 12
interrupt_stub 13
interrupt_stub 14
interrupt_stub 16
interrupt_stub 17
interrupt_stub 18
interrupt_stub 19

// IRQs (vorausgesetzt diese sind nach 0x20 bis 0x2f gemappt)
interrupt_stub 32
interrupt_stub 33
interrupt_stub 34
interrupt_stub 35
interrupt_stub 36
interrupt_stub 37
interrupt_stub 38
interrupt_stub 39
interrupt_stub 40
interrupt_stub 41
interrupt_stub 42
interrupt_stub 43
interrupt_stub 44
interrupt_stub 45
interrupt_stub 46
interrupt_stub 47

// Systemaufruf
interrupt_stub 48

_isr_common:
	vmcall
	iretq
