#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <elkvm.h>
#include <idt.h>
#include <pager.h>
#include <vcpu.h>

int elkvm_idt_setup(struct kvm_vm *vm) {

	uint64_t default_offset;
	int err = elkvm_idt_load_default_handler(vm, &default_offset);

	/* for now fill the idt with all 256 entries empty */
	for(int i = 0; i < 256; i++) {
		uint64_t offset = default_offset;
		struct kvm_idt_entry *entry = vm->region[MEMORY_REGION_IDT].host_base_p + 
			i * sizeof(struct kvm_idt_entry);
		//switch(i) {
		//		case IDT_ENTRY_PF:
		//				;
		//				uint64_t host_pf_handler = load_pfhandler(ram, size);
		//				offset = host_pf_handler - (uint64_t)ram;
		//				printf("SETTING pf_handler at: 0x%lx\n", offset);
		//			break;
		//	default:
		//		offset = 0x0;
		//		break;
		//}
		entry->offset1 = offset & 0xFFFF;
		entry->offset2 = (offset >> 16) & 0xFFFF;
		entry->offset3 = (uint32_t)(offset >> 32);

		entry->selector = 0x0008;
		entry->idx = 0x0;
		entry->flags = INTERRUPT_ENTRY_PRESENT | IT_TRAP_GATE | IT_LONG_IDT;
		entry->reserved = 0x0;
	}


	/* create a page for the idt */
	err = kvm_pager_create_mapping(&vm->pager, 
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
	vcpu->sregs.idt.limit = 0xFFF;

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
		buf += bytes;
	}

	return 0;
}

void elkvm_idt_dump(struct kvm_vm *vm) {
	struct kvm_idt_entry *entry = 
		(struct kvm_idt_entry *)vm->region[MEMORY_REGION_IDT].host_base_p;
	printf("\n Interrupt Descriptor Table:\n");
	printf(" ---------------------------\n\n");
	printf("Vector\tSelector\tOffset\tidx\tflags\n");
	for(int i = 0; i < 256; i++) {
		printf("%i\t0x%4x\t0x%016lx\t%u\t%u\n", i, entry->selector,
				idt_entry_offset(entry), entry->idx, 
				entry->flags);
	}
}	

void elkvm_idt_dump_isr(struct kvm_vm *vm, int iv) {
	struct kvm_vcpu *vcpu = vm->vcpus->vcpu;
	struct kvm_idt_entry *entry = vm->region[MEMORY_REGION_IDT].host_base_p +
		iv * sizeof(struct kvm_idt_entry);
	uint64_t guest_isr = idt_entry_offset(entry);
	printf("guest_isr: 0x%lx\n", guest_isr);
	char *isr = kvm_pager_get_host_p(&vm->pager, guest_isr);
	printf("isr: %p\n", isr);

	ud_set_input_buffer(&vcpu->ud_obj, isr, 9);

	printf("\n ISR Code for Interrupt Vector %3i:\n", iv);
	printf(  " ----------------------------------\n");
	while(ud_disassemble(&vcpu->ud_obj)) {
		printf(" %s\n", ud_insn_asm(&vcpu->ud_obj));
	}
	printf("\n");

	return;
}
