#include <elkvm.h>
#include <gdt.h>
#include <vcpu.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

int elkvm_gdt_setup(struct kvm_vm *vm) {
	
	memset(vm->region[MEMORY_REGION_GDT].host_base_p, 0,
		 sizeof(struct elkvm_gdt_segment_descriptor));

	struct elkvm_gdt_segment_descriptor *entry = 
		vm->region[MEMORY_REGION_GDT].host_base_p +
		sizeof(struct elkvm_gdt_segment_descriptor);

	/* code segment */
	elkvm_gdt_create_segment_descriptor(entry, 0x0, 0xFFFFFFFF,
			GDT_SEGMENT_READABLE | GDT_SEGMENT_EXECUTABLE | GDT_SEGMENT_BIT |
			GDT_SEGMENT_PRESENT,
			GDT_SEGMENT_PAGE_GRANULARITY | GDT_SEGMENT_PROTECTED_32 | GDT_SEGMENT_LONG);

	entry++;

	/* data segment */
	elkvm_gdt_create_segment_descriptor(entry, 0x0, 0xFFFFFFFF,
			GDT_SEGMENT_WRITEABLE | GDT_SEGMENT_BIT | GDT_SEGMENT_PRESENT,
			GDT_SEGMENT_PAGE_GRANULARITY | GDT_SEGMENT_PROTECTED_32 | GDT_SEGMENT_LONG);

	entry++;

	/* stack segment */
	elkvm_gdt_create_segment_descriptor(entry, 0x0, 0xFFFFFFFF,
			GDT_SEGMENT_WRITEABLE | GDT_SEGMENT_BIT | GDT_SEGMENT_PRESENT,
			GDT_SEGMENT_PAGE_GRANULARITY | GDT_SEGMENT_PROTECTED_32 | GDT_SEGMENT_LONG);

	entry++;

	/* task state segment */
	elkvm_gdt_create_segment_descriptor(entry, 0x0, 0xFFFFFFFF,
			0x9 | GDT_SEGMENT_PRESENT,
			GDT_SEGMENT_PAGE_GRANULARITY | GDT_SEGMENT_PROTECTED_32 | GDT_SEGMENT_LONG);

	struct kvm_vcpu *vcpu = vm->vcpus->vcpu;

	int err = kvm_vcpu_get_regs(vcpu);
	if(err) {
		return err;
	}

	vcpu->sregs.gdt.base = vm->region[MEMORY_REGION_GDT].guest_virtual;
	vcpu->sregs.gdt.limit = vm->region[MEMORY_REGION_GDT].guest_virtual +
		4 * 8;

	err = kvm_vcpu_set_regs(vcpu);
	if(err) {
		return err;
	}

	err = kvm_pager_create_mapping(&vm->pager, 
			vm->region[MEMORY_REGION_GDT].host_base_p,
			vm->region[MEMORY_REGION_GDT].guest_virtual);
	if(err) {
		return err;
	}

	elkvm_gdt_dump(vm);

	return 0;
}
