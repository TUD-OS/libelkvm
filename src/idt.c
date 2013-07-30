#include <elkvm.h>
#include <idt.h>
#include <pager.h>
#include <vcpu.h>

int elkvm_idt_setup(struct kvm_vm *vm) {
	/* for now fill the idt with all 256 entries empty */
	for(int i = 0; i < 256; i++) {
		uint64_t offset;
		struct kvm_idt_entry *entry = vm->region[MEMORY_REGION_IDT].host_base_p + 
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


	/* create a page for the idt */
	int err = kvm_pager_create_mapping(&vm->pager, 
			vm->region[MEMORY_REGION_IDT].host_base_p, 
			vm->region[MEMORY_REGION_IDT].guest_virtual);
	if(err) {
		return err;
	}

	/* set the idtr accordingly */
	struct kvm_vcpu *vcpu = vm->vcpus->vcpu;
	err = kvm_vcpu_get_regs(vcpu);
	if(err) {
		return err;
	}

	vcpu->sregs.idt.base = vm->region[MEMORY_REGION_IDT].guest_virtual;
	vcpu->sregs.idt.limit = 0x1000;

	err = kvm_vcpu_set_regs(vcpu);

	return err;
}

int elkvm_idt_load_default_handler(struct kvm_vm *vm, uint64_t *off) {
	vm->region[MEMORY_REGION_IDTH].region_size = 0x1000;
	vm->region[MEMORY_REGION_IDTH].host_base_p = 
		vm->region[MEMORY_REGION_IDT].host_base_p - 
		vm->region[MEMORY_REGION_IDTH].region_size;
	vm->region[MEMORY_REGION_IDTH].guest_virtual = 
		vm->region[MEMORY_REGION_IDT].guest_virtual - 
		vm->region[MEMORY_REGION_IDTH].region_size;
	vm->region[MEMORY_REGION_IDTH].grows_downward = 0;

	int err = kvm_pager_create_mapping(&vm->pager, 
			vm->region[MEMORY_REGION_IDTH].host_base_p, 
			vm->region[MEMORY_REGION_IDTH].guest_virtual);
	if(err) {
		return err;
	}

	int fd = open("/home/flo/Dokumente/projekte/libelkvm/res/vmxoff", O_RDONLY);
	if(fd < 0) {
		return -errno;
	}

	char *buf = vm->region[MEMORY_REGION_IDTH].host_base_p;
	*off = (uint64_t)vm->region[MEMORY_REGION_IDTH].guest_virtual;
	int bufsize = 0x1000;
	int bytes = 0;
	while((bytes = read(fd, buf, bufsize)) > 0) {
		printf("read %i bytes to %p\n", bytes, buf);
		buf += bytes;
	}

	printf("%.*lx\n", bytes, *(uint64_t *)vm->region[MEMORY_REGION_IDTH].host_base_p);

	return 0;
}

void elkvm_idt_dump(struct kvm_vm *vm) {
	struct kvm_idt_entry *entry = 
		(struct kvm_idt_entry *)vm->region[MEMORY_REGION_IDT].host_base_p;
	printf("\n Interrupt Descriptor Table:\n");
	printf(" ---------------------------\n\n");
	printf("Vector\tSelector\tOffset\tidx\tflags\n");
	for(int i = 0; i < 256; i++) {
		uint64_t offset = entry->offset1 | ((uint64_t)entry->offset2 << 16) | 
			((uint64_t)entry->offset3 << 32);
		printf("%i\t0x%4x\t0x%016lx\t%u\t%u\n", i, entry->selector, offset, entry->idx, 
				entry->flags);
	}
}	
