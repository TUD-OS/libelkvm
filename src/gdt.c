#include <elkvm.h>
#include <gdt.h>
#include <syscall.h>
#include <tss.h>
#include <vcpu.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

int elkvm_gdt_setup(struct kvm_vm *vm) {
	
	vm->gdt_region = elkvm_region_create(vm,
				GDT_NUM_ENTRIES * sizeof(struct elkvm_gdt_segment_descriptor));

	vm->gdt_region->guest_virtual = kvm_pager_map_kernel_page(&vm->pager,
			vm->gdt_region->host_base_p, 0, 0);
	if(vm->gdt_region->guest_virtual == 0) {
		return -ENOMEM;
	}

	/* create a null entry, as required by x86 */
	memset(vm->gdt_region->host_base_p, 0,
		 sizeof(struct elkvm_gdt_segment_descriptor));

	struct elkvm_gdt_segment_descriptor *entry = 
		vm->gdt_region->host_base_p + sizeof(struct elkvm_gdt_segment_descriptor);

	/* user code segment */
	elkvm_gdt_create_segment_descriptor(entry, 0x0, 0xFFFFFFFF,
			GDT_SEGMENT_READABLE | GDT_SEGMENT_EXECUTABLE | GDT_SEGMENT_BIT |
			GDT_SEGMENT_PRESENT  | GDT_SEGMENT_PRIVILEDGE_USER | GDT_SEGMENT_DIRECTION_BIT,
			GDT_SEGMENT_PAGE_GRANULARITY | GDT_SEGMENT_LONG);
	uint64_t cs_selector = (uint64_t)entry - (uint64_t)vm->gdt_region->host_base_p;

	entry++;

	/* user stack segment */
	elkvm_gdt_create_segment_descriptor(entry, 0x0, 0xFFFFFFFF,
			GDT_SEGMENT_PRESENT | GDT_SEGMENT_WRITEABLE | GDT_SEGMENT_BIT | 
			GDT_SEGMENT_PRIVILEDGE_USER,
			GDT_SEGMENT_PAGE_GRANULARITY | GDT_SEGMENT_LONG );
	entry++;

	/* user data segment */
	elkvm_gdt_create_segment_descriptor(entry, 0x0, 0xFFFFFFFF,
			GDT_SEGMENT_WRITEABLE | GDT_SEGMENT_BIT | GDT_SEGMENT_PRESENT,
			GDT_SEGMENT_PAGE_GRANULARITY | GDT_SEGMENT_LONG );

	entry++;

	struct elkvm_memory_region *tss_region = elkvm_region_create(vm,
			sizeof(struct elkvm_tss64));
	/* setup the tss, before loading the segment descriptor */
	int err = elkvm_tss_setup64(vm, tss_region);
	if(err) {
		return -err;
	}

	/* task state segment */
	elkvm_gdt_create_segment_descriptor(entry,
			tss_region->guest_virtual & 0xFFFFFFFF,
			sizeof(struct elkvm_tss64),
			0x9 | GDT_SEGMENT_PRESENT,
			GDT_SEGMENT_LONG);

	uint64_t tr_selector = (uint64_t)entry -
		(uint64_t)vm->gdt_region->host_base_p;

	/*
	 * tss entry has 128 bits, make a second entry to account for that
	 * the upper part of base is in the beginning of that second entry
	 * rest is ignored or must be 0, just set everything to 0
	 */
	entry++;
	uint64_t *upper_tss = (uint64_t *)entry;
	*upper_tss = tss_region->guest_virtual >> 32;
	entry++;

	/* kernel code segment */
	elkvm_gdt_create_segment_descriptor(entry, 0x0, 0xFFFFFFFF,
			GDT_SEGMENT_READABLE | GDT_SEGMENT_EXECUTABLE | GDT_SEGMENT_BIT |
			GDT_SEGMENT_PRESENT | GDT_SEGMENT_DIRECTION_BIT,
			GDT_SEGMENT_PAGE_GRANULARITY | GDT_SEGMENT_LONG);
	uint64_t kernel_cs_selector = 
		(uint64_t)entry - (uint64_t)vm->gdt_region->host_base_p;

	entry++;

	/* kernel stack segment */
	elkvm_gdt_create_segment_descriptor(entry, 0x0, 0xFFFFFFFF,
			GDT_SEGMENT_WRITEABLE | GDT_SEGMENT_BIT | GDT_SEGMENT_PRESENT,
			GDT_SEGMENT_PAGE_GRANULARITY | GDT_SEGMENT_LONG );
	entry++;


	struct kvm_vcpu *vcpu = vm->vcpus->vcpu;
	uint64_t syscall_star = kernel_cs_selector;
	uint64_t sysret_star = cs_selector | 0x3;
	uint64_t star = (sysret_star << 48) | (syscall_star << 32);

	err = kvm_vcpu_set_msr(vcpu,
			VCPU_MSR_STAR,
			star);
	if(err) {
		return err;
	}

	err = kvm_vcpu_get_regs(vcpu);
	if(err) {
		return err;
	}

	vcpu->sregs.gdt.base = vm->gdt_region->guest_virtual;
	vcpu->sregs.gdt.limit = GDT_NUM_ENTRIES * 8 - 1;

	vcpu->sregs.tr.base = tss_region->guest_virtual;
	vcpu->sregs.tr.limit = sizeof(struct elkvm_tss64);
	vcpu->sregs.tr.selector = tr_selector;

	err = kvm_vcpu_set_regs(vcpu);
	if(err) {
		return err;
	}

	return 0;
}

int elkvm_gdt_create_segment_descriptor(struct elkvm_gdt_segment_descriptor *entry,
	uint32_t base, uint32_t limit, uint8_t access, uint8_t flags) {

	if(base & 0xFFF00000) {
		return -EINVAL;
	}

	entry->base1        = base  & 0xFFFF;
	entry->base2        = (base >> 16) & 0xFF;
	entry->base3        = (base >> 24);
	entry->limit1       = limit & 0xFFFF;
	entry->limit2_flags = ((limit >> 16) & 0xF) | ((uint8_t)flags << 4);
	entry->access       = access;

	return 0;
}

int elkvm_calc_segment_regs(struct kvm_vcpu *vcpu, struct elkvm_gdt_segment_descriptor *entry, 
		int num_entries) {
	return -1;
}

void elkvm_gdt_dump(struct kvm_vm *vm) {

	printf("\n Global Descriptor Table:\n");
	printf(  " ------------------------\n");
	printf(  " host addr\tselector\tbase\t\tlimit\tC DPL P\t\tL D\n");

	for(int i = 0; i < GDT_NUM_ENTRIES; i++) {
		struct elkvm_gdt_segment_descriptor *entry = vm->gdt_region->host_base_p +
			i * sizeof(struct elkvm_gdt_segment_descriptor);
		uint16_t selector = i * sizeof(struct elkvm_gdt_segment_descriptor);

		printf(" %p\t0x%4x\t\t0x%08x\t0x%05x\t%1i   %1i %1i (0x%02x)\t %1i %1i (0x%1x)\n",
			entry,
			selector,
			gdt_base(entry),
			gdt_limit(entry),
			(entry->access >> 2) & 0x1,
			(entry->access >> 5) & 0x3,
			(entry->access >> 7),
			entry->access,
			(entry->limit2_flags >> 5) & 0x1,
			(entry->limit2_flags >> 6) & 0x1,
			gdt_flags(entry));
	}

	printf("\n");
}
