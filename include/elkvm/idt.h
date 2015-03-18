/* * libelkvm - A library that allows execution of an ELF binary inside a virtual
 * machine without a full-scale operating system
 * Copyright (C) 2013-2015 Florian Pester <fpester@os.inf.tu-dresden.de>, Björn
 * Döbel <doebel@os.inf.tu-dresden.de>,   economic rights: Technische Universitaet
 * Dresden (Germany)
 *
 * This file is part of libelkvm.
 *
 * libelkvm is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * libelkvm is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libelkvm.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <memory>

#include <elkvm/elkvm.h>
#include <elkvm/region.h>
#include <elkvm/types.h>

int elkvm_idt_setup(Elkvm::RegionManager &rm, std::shared_ptr<Elkvm::VCPU> vcpu,
    Elkvm::elkvm_flat *);

struct kvm_idt_entry {
    uint16_t offset1;
    uint16_t selector;
    /*
     * in long mode lower three bits of idx are
     * used for ist index
     */
    uint8_t idx;
    uint8_t flags;
    uint16_t offset2;
    uint32_t offset3;
    uint32_t reserved;
}__attribute__((packed));

#define IT_CALL_GATE      0xC
#define IT_INTERRUPT_GATE 0xE
#define IT_TRAP_GATE      0xF

#define IT_LONG_IDT 8

#define INTERRUPT_ENTRY_PRESENT 128

static inline
uint64_t idt_entry_offset(struct kvm_idt_entry *entry) {
        return entry->offset1 | ((uint64_t)entry->offset2 << 16) |
            ((uint64_t)entry->offset3 << 32);
}


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
