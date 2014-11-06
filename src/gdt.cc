#include <algorithm>
#include <cstring>
#include <memory>

#include <errno.h>
#include <stdio.h>

#include <elkvm/elkvm.h>
#include <elkvm/elkvm-internal.h>
#include <elkvm/kvm.h>
#include <elkvm/gdt.h>
#include <elkvm/region.h>
#include <elkvm/region_manager.h>
#include <elkvm/tss.h>
#include <elkvm/vcpu.h>

int elkvm_gdt_setup(Elkvm::RegionManager &rm, std::shared_ptr<VCPU> vcpu) {
  std::shared_ptr<Elkvm::Region> gdt_region =
    rm.allocate_region(
				GDT_NUM_ENTRIES * sizeof(struct elkvm_gdt_segment_descriptor));

  guestptr_t guest_virtual =
    rm.get_pager().map_kernel_page(
      gdt_region->base_address(), 0);
  assert(guest_virtual != 0x0 && "could not map gdt");
  gdt_region->set_guest_addr(guest_virtual);

	/* create a null entry, as required by x86 */
	memset(gdt_region->base_address(), 0,
		 sizeof(struct elkvm_gdt_segment_descriptor));

	struct elkvm_gdt_segment_descriptor *entry =
    reinterpret_cast<struct elkvm_gdt_segment_descriptor *>(
		reinterpret_cast<char *>(gdt_region->base_address())
    + sizeof(struct elkvm_gdt_segment_descriptor));

	/* user stack segment */
	elkvm_gdt_create_segment_descriptor(entry, 0x0, 0xFFFFFFFF,
			GDT_SEGMENT_PRESENT | GDT_SEGMENT_WRITEABLE | GDT_SEGMENT_BIT |
			GDT_SEGMENT_PRIVILEDGE_USER,
			GDT_SEGMENT_PAGE_GRANULARITY | GDT_SEGMENT_LONG );
	uint64_t ss_selector = (uint64_t)entry - (uint64_t)gdt_region->base_address();
	entry++;

	/* user code segment */
	elkvm_gdt_create_segment_descriptor(entry, 0x0, 0xFFFFFFFF,
			GDT_SEGMENT_READABLE | GDT_SEGMENT_EXECUTABLE | GDT_SEGMENT_BIT |
			GDT_SEGMENT_PRESENT  | GDT_SEGMENT_PRIVILEDGE_USER | GDT_SEGMENT_DIRECTION_BIT,
			GDT_SEGMENT_PAGE_GRANULARITY | GDT_SEGMENT_LONG);

	entry++;

	/* user data segment */
	elkvm_gdt_create_segment_descriptor(entry, 0x0, 0xFFFFFFFF,
			GDT_SEGMENT_WRITEABLE | GDT_SEGMENT_BIT | GDT_SEGMENT_PRESENT,
			GDT_SEGMENT_PAGE_GRANULARITY | GDT_SEGMENT_LONG );

	entry++;

  std::shared_ptr<Elkvm::Region> tss_region =
    rm.allocate_region(
      sizeof(struct elkvm_tss64));
	/* setup the tss, before loading the segment descriptor */
	int err = elkvm_tss_setup64(vcpu, rm, tss_region);
	if(err) {
		return -err;
	}

	/* task state segment */
	elkvm_gdt_create_segment_descriptor(entry,
			tss_region->guest_address() & 0xFFFFFFFF,
			sizeof(struct elkvm_tss64),
			0x9 | GDT_SEGMENT_PRESENT,
			GDT_SEGMENT_LONG);

	uint64_t tr_selector = (uint64_t)entry
    - (uint64_t)gdt_region->base_address();

	/*
	 * tss entry has 128 bits, make a second entry to account for that
	 * the upper part of base is in the beginning of that second entry
	 * rest is ignored or must be 0, just set everything to 0
	 */
	entry++;
	uint64_t *upper_tss = (uint64_t *)entry;
	*upper_tss = tss_region->guest_address() >> 32;
	entry++;

	/* kernel code segment */
	elkvm_gdt_create_segment_descriptor(entry, 0x0, 0xFFFFFFFF,
			GDT_SEGMENT_READABLE | GDT_SEGMENT_EXECUTABLE | GDT_SEGMENT_BIT |
			GDT_SEGMENT_PRESENT | GDT_SEGMENT_DIRECTION_BIT,
			GDT_SEGMENT_PAGE_GRANULARITY | GDT_SEGMENT_LONG);
	uint64_t kernel_cs_selector =
		(uint64_t)entry - (uint64_t)gdt_region->base_address();

	entry++;

	/* kernel stack segment */
	elkvm_gdt_create_segment_descriptor(entry, 0x0, 0xFFFFFFFF,
			GDT_SEGMENT_WRITEABLE | GDT_SEGMENT_BIT | GDT_SEGMENT_PRESENT,
			GDT_SEGMENT_PAGE_GRANULARITY | GDT_SEGMENT_LONG );
	entry++;


	uint64_t syscall_star = kernel_cs_selector;
	uint64_t sysret_star = (ss_selector - 0x8) | 0x3;
	uint64_t star = (sysret_star << 48) | (syscall_star << 32);

	err = kvm_vcpu_set_msr(vcpu,
			VCPU_MSR_STAR,
			star);
	if(err) {
		return err;
	}

	err = vcpu->get_sregs();
	if(err) {
		return err;
	}

	vcpu->sregs.gdt.base = gdt_region->guest_address();
	vcpu->sregs.gdt.limit = GDT_NUM_ENTRIES * 8 - 1;

	vcpu->sregs.tr.base = tss_region->guest_address();
	vcpu->sregs.tr.limit = sizeof(struct elkvm_tss64);
	vcpu->sregs.tr.selector = tr_selector;

	err = kvm_vcpu_set_sregs(vcpu);
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

