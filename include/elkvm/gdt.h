#pragma once

#include <memory>

#include <elkvm/region.h>
#include <elkvm/vcpu.h>

int elkvm_gdt_setup(Elkvm::RegionManager &rm, std::shared_ptr<struct kvm_vcpu> vcpu);

struct elkvm_gdt_segment_descriptor {
	uint16_t limit1;
	uint16_t base1;
	uint8_t base2;
	uint8_t access;
	uint8_t limit2_flags;
	uint8_t base3;
};

#define GDT_SEGMENT_WRITEABLE          2
#define GDT_SEGMENT_READABLE           2
#define GDT_SEGMENT_DIRECTION_BIT      4
#define GDT_SEGMENT_EXECUTABLE         8
#define GDT_SEGMENT_BIT	              16
#define GDT_SEGMENT_PRIVILEDGE_USER   96
#define GDT_SEGMENT_PRESENT          128
#define GDT_SEGMENT_LONG               2
#define GDT_SEGMENT_PROTECTED_32       4
#define GDT_SEGMENT_PAGE_GRANULARITY   8

/*
 * we have 2 code segments, 2 stack segments, a data segment and a
 * tss segment
 * make room for an additional entry, because the entry for
 * tss has twice the size in long mode
 */
#define GDT_NUM_ENTRIES 8

int elkvm_gdt_create_segment_descriptor(struct elkvm_gdt_segment_descriptor *,
		uint32_t, uint32_t, uint8_t, uint8_t);

static inline
uint32_t gdt_base(struct elkvm_gdt_segment_descriptor *entry) {
	return entry->base1 | ((uint32_t)entry->base2 << 16) |
	 ((uint32_t)entry->base3 << 24);
}

static inline
uint32_t gdt_limit(struct elkvm_gdt_segment_descriptor *entry) {
	return entry->limit1 | ((uint32_t)(entry->limit2_flags & 0xF) << 16);
}

static inline
uint8_t gdt_flags(struct elkvm_gdt_segment_descriptor *entry) {
	return entry->limit2_flags >> 4;
}
