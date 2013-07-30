#include <elkvm.h>
#include <idt.h>
#include <pager.h>

int elkvm_idt_setup(struct kvm_vm *vm) {
	//fill idt with all 256 entries
	for(int i = 0; i < 256; i++) {
		uint64_t offset;
		struct kvm_idt_entry *entry = vm->region[4].host_base_p + 
			i * sizeof(struct kvm_idt_entry);
		switch(i) {
//			case IDT_ENTRY_PF:
//					;
//					uint64_t host_pf_handler = load_pfhandler(ram, size);
//					offset = host_pf_handler - (uint64_t)ram;
//					printf("SETTING pf_handler at: 0x%lx\n", offset);
//				break;
			default:
				offset = 0x0;
				break;
		}
		entry->offset1 = (uint16_t)((offset << 48) >> 48);
		entry->offset2 = (uint16_t)((offset << 32) >> 48);
		entry->offset3 = (uint32_t)(offset >> 32);

		entry->selector = 0x1000;
		entry->idx = 0x0;
		entry->flags = INTERRUPT_ENTRY_PRESENT | IT_INTERRUPT_GATE;
		entry->reserved = 0x0;
	}

	//create a page for the idt
	int err = kvm_pager_create_mapping(&vm->pager, vm->region[4].host_base_p, 
			vm->region[4].guest_virtual);

	return err;
}

