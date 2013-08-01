#include <elkvm.h>
#include <gdt.h>

int elkvm_gdt_setup(struct kvm_vm *vm) {
	
	for(int i = 0; i < 3; i++) {
		struct elkvm_gdt_entry *entry = vm->region[MEMORY_REGION_GDT].host_base_p + 
			i * sizeof(struct elkvm_gdt_entry);

		entry->limit1 = 0xFFFF;
		entry->base1 = 0x0;
		entry->access = GDT_SEGMENT_WRITEABLE | GDT_SEGMENT_EXECUTABLE | GDT_BIT_SET | 
			GDT_SEGMENT_PRESENT;
		entry->limit2_flags = 0xF | GDT_SEGMENT_PAGE_GRANULARITY | GDT_SEGMENT_PROTECTED;
	}

	int err = kvm_pager_create_mapping(&vm->pager, 
			vm->region[MEMORY_REGION_GDT].host_base_p,
			vm->region[MEMORY_REGION_GDT].guest_virtual);
	if(err) {
		return err;
	}

	return 0;
}
