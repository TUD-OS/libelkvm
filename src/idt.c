#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <elkvm.h>
#include <flats.h>
#include <idt.h>
#include <pager.h>
#include <vcpu.h>

int elkvm_idt_setup(struct kvm_vm *vm, struct elkvm_flat *default_handler) {

	vm->idt_region = elkvm_region_create(
			vm,
			256 * sizeof(struct kvm_idt_entry));

	/* for now fill the idt with all 256 entries empty */
	for(int i = 0; i < 256; i++) {
		uint64_t offset = default_handler->region->guest_virtual;
		struct kvm_idt_entry *entry = vm->idt_region->host_base_p + 
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
		entry->idx = 0x1;
		entry->flags = INTERRUPT_ENTRY_PRESENT | IT_TRAP_GATE | IT_LONG_IDT;
		entry->reserved = 0x0;
	}


	/* create a page for the idt */
	vm->idt_region->guest_virtual = kvm_pager_map_kernel_page(&vm->pager,
			vm->idt_region->host_base_p, 0, 0);
	if(vm->idt_region->guest_virtual == 0) {
		return -ENOMEM;
	}

	/* set the idtr accordingly */
	struct kvm_vcpu *vcpu = vm->vcpus->vcpu;
	int err = kvm_vcpu_get_regs(vcpu);
	if(err) {
		return err;
	}

	vcpu->sregs.idt.base = vm->idt_region->guest_virtual;
	vcpu->sregs.idt.limit = 0xFFF;

	err = kvm_vcpu_set_regs(vcpu);

	return err;
}

void elkvm_idt_dump(struct kvm_vm *vm) {
	struct kvm_idt_entry *entry = 
		(struct kvm_idt_entry *)vm->idt_region->host_base_p;
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
	struct kvm_idt_entry *entry = vm->idt_region->host_base_p +
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
