#include <algorithm>
#include <memory>

#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <elkvm/elkvm.h>
#include <elkvm/elkvm-internal.h>
#include <elkvm/kvm.h>
#include <elkvm/idt.h>
#include <elkvm/pager.h>
#include <elkvm/region.h>
#include <elkvm/regs.h>
#include <elkvm/vcpu.h>

int elkvm_idt_setup(Elkvm::RegionManager &rm,
    std::shared_ptr<Elkvm::VCPU> vcpu,
    Elkvm::elkvm_flat *default_handler) {
  std::shared_ptr<Elkvm::Region> idt_region =
    rm.allocate_region(
			256 * sizeof(struct kvm_idt_entry));

  /* default handler defines 48 entries, that push the iv to the stack */
	for(int i = 0; i < 48; i++) {
		uint64_t offset = default_handler->region->guest_address() + i * 9;
		struct kvm_idt_entry *entry =
      reinterpret_cast<struct kvm_idt_entry *>(
          reinterpret_cast<char *>(idt_region->base_address()) +
			i * sizeof(struct kvm_idt_entry));

		entry->offset1 = offset & 0xFFFF;
		entry->offset2 = (offset >> 16) & 0xFFFF;
		entry->offset3 = (uint32_t)(offset >> 32);

		entry->selector = 0x0030;
		entry->idx = 0x1;
		entry->flags = INTERRUPT_ENTRY_PRESENT | IT_TRAP_GATE | IT_LONG_IDT;
		entry->reserved = 0x0;
	}


	/* create a page for the idt */
	guestptr_t guest_virtual =
    rm.get_pager().map_kernel_page(
			idt_region->base_address(), 0);
  assert(guest_virtual != 0x0);
  idt_region->set_guest_addr(guest_virtual);

  Elkvm::Segment idt(idt_region->guest_address(), 0xFFF);
  vcpu->set_reg(Elkvm::Seg_t::idt, idt);

	int err = vcpu->set_sregs();

	return err;
}
