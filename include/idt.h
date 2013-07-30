#pragma once

#include "elkvm.h"
#include "pager.h"

struct kvm_idt_entry {
	uint16_t offset1;
	uint16_t selector;
	//only use lower three bits of idx!
	uint8_t idx;
	uint8_t flags;
	uint16_t offset2;
	uint32_t offset3;
	uint32_t reserved;
}__attribute__((packed));

#define IT_INTERRUPT_GATE 6
#define IT_TRAP_GATE 7
#define IT TASK_GATE 5

#define INTERRUPT_ENTRY_PRESENT 128

int elkvm_idt_setup(struct kvm_vm *);
int elkvm_idt_load_default_handler(struct kvm_vm *, uint64_t *);

void elkvm_idt_dump(struct kvm_vm *);

#define IDT_ENTRY_DE  0x00
#define IDT_ENTRY_DB  0x01
#define IDT_ENTRY_NMI 0x02
#define IDT_ENTRY_BP  0x03
#define IDT_ENTRY_OF  0x04
#define IDT_ENTRY_BR  0x05
#define IDT_ENTRY_UD  0x06
#define IDT_ENTRY_NM  0x07
#define IDT_ENTRY_DF  0x08
#define IDT_ENTRY_CSO 0x09
#define IDT_ENTRY_TS  0x0a
#define IDT_ENTRY_NP  0x0b
#define IDT_ENTRY_SS  0x0c
#define IDT_ENTRY_GP  0x0d
#define IDT_ENTRY_PF  0x0e
//0x0f is reserved
#define IDT_ENTRY_MF  0x10
#define IDT_ENTRY_AC  0x11
#define IDT_ENTRY_MC  0x12
#define IDT_ENTRY_XF  0x13
//0x14 - 0x1d are reserved
#define IDT_ENTRY_SX  0x1e
//0x1f is reserved

