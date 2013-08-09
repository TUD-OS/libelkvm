#pragma once

struct elkvm_memory_region {
	void *host_base_p;
	uint64_t guest_virtual;
	uint64_t region_size;
	int grows_downward;
	int used;
	struct elkvm_memory_region *lc;
	struct elkvm_memory_region *rc;
};

struct elkvm_memory_region *elkvm_region_create(struct kvm_vm *, uint64_t);
int elkvm_region_split(struct kvm_vm *, struct elkvm_memory_region *);

/*
 * There will be 9 memory regions in the system_chunk:
 * 1. text
 * 2. data
 * 3. bss (growing upward)
 * 4. kernel (interrupt) stack (growing downward)
 * 5. user stack (growing downward)
 * 6. env, which will hold the environment strings
 * 7. idth, which will hold the binaries the idt will point to
 * 8. idt, which will hold the interrupt descriptor table
 * 9. pt, which will hold the page tables
 */
#define MEMORY_REGION_TEXT   0
#define MEMORY_REGION_DATA   1
#define MEMORY_REGION_BSS    2
#define MEMORY_REGION_KSTACK 3
#define MEMORY_REGION_STACK  4
#define MEMORY_REGION_ENV    5
#define MEMORY_REGION_IDTH   6
#define MEMORY_REGION_IDT    7
#define MEMORY_REGION_GDT    8
#define MEMORY_REGION_PTS    9

#define MEMORY_REGION_COUNT 10
