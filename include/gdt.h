#include "elkvm.h"

struct elkvm_gdt_entry {
	uint16_t limit1;
	uint16_t base1;
	uint8_t base2;
	uint8_t access;
	uint8_t limit2_flags;
	uint8_t base3;
};

#define GDT_SEGMENT_WRITEABLE 2
#define GDT_SEGMENT_EXECUTABLE 8
#define GDT_BIT_SET 16
#define GDT_SEGMENT_PRESENT 128
#define GDT_SEGMENT_PROTECTED 64
#define GDT_SEGMENT_PAGE_GRANULARITY 128

int elkvm_gdt_setup(struct kvm_vm *);

