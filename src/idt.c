#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <elkvm.h>
#include <idt.h>
#include <pager-c.h>
#include <vcpu.h>
#include "flats.h"

int elkvm_idt_setup(struct kvm_vm *vm, struct elkvm_flat *default_handler) {

	vm->idt_region = elkvm_region_create(
			256 * sizeof(struct kvm_idt_entry));

  /* default handler defines 48 entries, that push the iv to the stack */
	for(int i = 0; i < 48; i++) {
		uint64_t offset = default_handler->region->guest_virtual + i * 9;
		struct kvm_idt_entry *entry = vm->idt_region->host_base_p +
			i * sizeof(struct kvm_idt_entry);

		entry->offset1 = offset & 0xFFFF;
		entry->offset2 = (offset >> 16) & 0xFFFF;
		entry->offset3 = (uint32_t)(offset >> 32);

		entry->selector = 0x0030;
		entry->idx = 0x1;
		entry->flags = INTERRUPT_ENTRY_PRESENT | IT_TRAP_GATE | IT_LONG_IDT;
		entry->reserved = 0x0;
	}


	/* create a page for the idt */
	vm->idt_region->guest_virtual = elkvm_pager_map_kernel_page(NULL,
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

	err = kvm_vcpu_set_sregs(vcpu);

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
    entry++;
	}
}

