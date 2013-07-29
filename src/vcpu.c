#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stropts.h>
#include <sys/mman.h>
#include <unistd.h>

#include <elkvm.h>
#include <stack.h>
#include <vcpu.h>

int kvm_vcpu_create(struct kvm_vm *vm, int mode) {
	if(vm->fd <= 0) {
		return -EIO;
	}

	struct kvm_vcpu *vcpu = malloc(sizeof(struct kvm_vcpu));
	memset(&vcpu->regs, 0, sizeof(struct kvm_regs));
	memset(&vcpu->sregs, 0, sizeof(struct kvm_sregs));
	vcpu->is_debug = 0;

	int vcpu_count = kvm_vm_vcpu_count(vm);
	vcpu->fd = ioctl(vm->fd, KVM_CREATE_VCPU, vcpu_count);
	if(vcpu->fd <= 0) {
		free(vcpu);
		return -1;
	}

	int err = kvm_vcpu_initialize_regs(vcpu, mode);
	if(err) {
		free(vcpu);
		return err;
	}

	vcpu->run_struct = mmap(NULL, sizeof(struct kvm_run), PROT_READ | PROT_WRITE, 
			MAP_SHARED, vcpu->fd, 0);
	if(vcpu->run_struct == NULL) {
		free(vcpu);
		return -1;
	}

	err = kvm_vcpu_add_tail(vm, vcpu);
	if(err) {
		free(vcpu);
		return err;
	}

	ud_init(&vcpu->ud_obj);
	switch(mode) {
		case VM_MODE_X86_64:
			ud_set_mode(&vcpu->ud_obj, 64);
	}
	ud_set_syntax(&vcpu->ud_obj, UD_SYN_INTEL);

	vcpu->vm = vm;
	return 0;
}

int kvm_vcpu_add_tail(struct kvm_vm *vm, struct kvm_vcpu *vcpu) {
	/* find the last entry in the vcpu list for this vm */
	struct vcpu_list *vl = vm->vcpus;
	while(vl != NULL && vl->next != NULL) {
		vl = vl->next;
	}

	struct vcpu_list *new_item = malloc(sizeof(struct vcpu_list));
	if(new_item == NULL) {
		return -ENOMEM;
	}

	new_item->next = NULL;
	new_item->vcpu = vcpu;
	if(vl == NULL) {
		vm->vcpus = new_item;
	} else {
		vl->next = new_item;
	}

	return 0;
}

int kvm_vcpu_initialize_regs(struct kvm_vcpu *vcpu, int mode) {
	switch(mode) {
		case VM_MODE_X86_64:
			return kvm_vcpu_initialize_long_mode(vcpu);
		default:
			return -1;
	}
}

int kvm_vcpu_set_rip(struct kvm_vcpu * vcpu, uint64_t rip) {
	int err = kvm_vcpu_get_regs(vcpu);
	if(err) {
		return err;
	}

	vcpu->regs.rip = rip;

	err = kvm_vcpu_set_regs(vcpu);
	if(err) {
		return err;
	}

	return 0;
}

int kvm_vcpu_set_cr3(struct kvm_vcpu *vcpu, uint64_t cr3) {
	assert(vcpu != NULL);

	int err = kvm_vcpu_get_regs(vcpu);
	if(err) {
		return err;
	}

	vcpu->sregs.cr3 = cr3;

	err = kvm_vcpu_set_regs(vcpu);
	if(err) {
		return err;
	}

	return 0;
}

int kvm_vcpu_get_regs(struct kvm_vcpu *vcpu) {
	if(vcpu->fd < 1) {
		return -EIO;
	}

	int err = ioctl(vcpu->fd, KVM_GET_REGS, &vcpu->regs);
	if(err) {
		return -errno;
	}

	err = ioctl(vcpu->fd, KVM_GET_SREGS, &vcpu->sregs);
	if(err) {
		return -errno;
	}

	return 0;
}

int kvm_vcpu_set_regs(struct kvm_vcpu *vcpu) {
	if(vcpu->fd < 1) {
		return -EIO;
	}

	int err = ioctl(vcpu->fd, KVM_SET_REGS, &vcpu->regs);
	if(err) {
		return -errno;
	}

	err = ioctl(vcpu->fd, KVM_SET_SREGS, &vcpu->sregs);
	if(err) {
		return -errno;
	}

	return 0;
}

int kvm_vcpu_destroy(struct kvm_vm *vm, struct kvm_vcpu *vcpu) {
	struct vcpu_list *vl = vm->vcpus;
	int found = 0;

	if(vl != NULL && vl->vcpu == vcpu) {
		vm->vcpus = vl->next;
		close(vl->vcpu->fd);
		free(vl->vcpu);
		free(vl);
		return 0;
	}

	while(vl != NULL && vl->next != NULL) {
		if(vl->next->vcpu == vcpu) {
			found = 1;
			break;
		}
		vl = vl->next;
	}

	if(!found) {
		return -1;
	}

	struct vcpu_list *old = vl->next;
	vl->next = vl->next->next;
	free(old);
	close(vcpu->fd);
	free(vcpu);

	return 0;
}

int kvm_vcpu_initialize_long_mode(struct kvm_vcpu *vcpu) {

	memset(&vcpu->regs, 0, sizeof(struct kvm_regs));
	vcpu->regs.rsp = LINUX_64_STACK_BASE;
	/* for some reason this needs to be set */
	vcpu->regs.rflags = 0x00000002;

	vcpu->sregs.cr0 = VCPU_CR0_FLAG_PAGING | VCPU_CR0_FLAG_CACHE_DISABLE |
			VCPU_CR0_FLAG_NOT_WRITE_THROUGH |
			VCPU_CR0_FLAG_PROTECTED;
	vcpu->sregs.cr4 = VCPU_CR4_FLAG_PAE;
	vcpu->sregs.cr2 = vcpu->sregs.cr3 = vcpu->sregs.cr8 = 0x0;
	vcpu->sregs.efer = VCPU_EFER_FLAG_LME;

	//TODO find out why this is!
	vcpu->sregs.apic_base = 0xfee00900;

	vcpu->sregs.cs.selector = 0x1000;
	vcpu->sregs.cs.base     = 0x0;
	vcpu->sregs.cs.limit    = 0xFFFFFFFF;
	vcpu->sregs.cs.type     = 0xb;
	vcpu->sregs.cs.present  = 0x1;
	vcpu->sregs.cs.dpl      = 0x0;
	vcpu->sregs.cs.db       = 0x0;
	vcpu->sregs.cs.s        = 0x1;
	vcpu->sregs.cs.l        = 0x1;
	vcpu->sregs.cs.g        = 0x1;
	vcpu->sregs.cs.avl      = 0x0;

	vcpu->sregs.ds.selector = 0x1000;
	vcpu->sregs.ds.base     = 0x0;
	vcpu->sregs.ds.limit    = 0xFFFFFFFF;
	vcpu->sregs.ds.type     = 0x3;
	vcpu->sregs.ds.present  = 0x1;
	vcpu->sregs.ds.dpl      = 0x0;
	vcpu->sregs.ds.db       = 0x0;
	vcpu->sregs.ds.s        = 0x1;
	vcpu->sregs.ds.l        = 0x0;
	vcpu->sregs.ds.g        = 0x1;
	vcpu->sregs.ds.avl      = 0x0;

	vcpu->sregs.es.selector = 0x0;
	vcpu->sregs.es.base     = 0x0;
	vcpu->sregs.es.limit    = 0xFFFFF;
	vcpu->sregs.es.type     = 0x3;
	vcpu->sregs.es.present  = 0x1;
	vcpu->sregs.es.dpl      = 0x0;
	vcpu->sregs.es.db       = 0x0;
	vcpu->sregs.es.s        = 0x1;
	vcpu->sregs.es.l        = 0x0;
	vcpu->sregs.es.g        = 0x0;
	vcpu->sregs.es.avl      = 0x0;

	vcpu->sregs.fs.selector = 0x0;
	vcpu->sregs.fs.base     = 0x0;
	vcpu->sregs.fs.limit    = 0xFFFFF;
	vcpu->sregs.fs.type     = 0x3;
	vcpu->sregs.fs.present  = 0x1;
	vcpu->sregs.fs.dpl      = 0x0;
	vcpu->sregs.fs.db       = 0x0;
	vcpu->sregs.fs.s        = 0x1;
	vcpu->sregs.fs.l        = 0x0;
	vcpu->sregs.fs.g        = 0x0;
	vcpu->sregs.fs.avl      = 0x0;

	vcpu->sregs.gs.selector = 0x0;
	vcpu->sregs.gs.base     = 0x10000;
	vcpu->sregs.gs.limit    = 0xFFFFF;
	vcpu->sregs.gs.type     = 0x3;
	vcpu->sregs.gs.present  = 0x1;
	vcpu->sregs.gs.dpl      = 0x0;
	vcpu->sregs.gs.db       = 0x0;
	vcpu->sregs.gs.s        = 0x1;
	vcpu->sregs.gs.l        = 0x0;
	vcpu->sregs.gs.g        = 0x0;
	vcpu->sregs.gs.avl      = 0x0;

	vcpu->sregs.tr.selector = 0x0;
	vcpu->sregs.tr.base     = 0x0;
	vcpu->sregs.tr.limit    = 0xFFFF;
	vcpu->sregs.tr.type     = 0xb;
	vcpu->sregs.tr.present  = 0x1;
	vcpu->sregs.tr.dpl      = 0x0;
	vcpu->sregs.tr.db       = 0x0;
	vcpu->sregs.tr.s        = 0x0;
	vcpu->sregs.tr.l        = 0x0;
	vcpu->sregs.tr.g        = 0x0;
	vcpu->sregs.tr.avl      = 0x0;

	vcpu->sregs.ldt.selector = 0x0;
	vcpu->sregs.ldt.base     = 0x0;
	vcpu->sregs.ldt.limit    = 0xFFFF;
	vcpu->sregs.ldt.type     = 0x2;
	vcpu->sregs.ldt.present  = 0x1;
	vcpu->sregs.ldt.dpl      = 0x0;
	vcpu->sregs.ldt.db       = 0x0;
	vcpu->sregs.ldt.s        = 0x0;
	vcpu->sregs.ldt.l        = 0x0;
	vcpu->sregs.ldt.g        = 0x0;
	vcpu->sregs.ldt.avl      = 0x0;

	vcpu->sregs.ss.selector = 0x1000;
	vcpu->sregs.ss.base     = 0x0;
	vcpu->sregs.ss.limit    = 0xFFFFFFFF;
	vcpu->sregs.ss.type     = 0x3;
	vcpu->sregs.ss.present  = 0x1;
	vcpu->sregs.ss.dpl      = 0x0;
	vcpu->sregs.ss.db       = 0x0;
	vcpu->sregs.ss.s        = 0x1;
	vcpu->sregs.ss.l        = 0x0;
	vcpu->sregs.ss.g        = 0x1;
	vcpu->sregs.ss.avl      = 0x0;

	vcpu->sregs.gdt.base  = 0x0;
	vcpu->sregs.gdt.limit = 0xFFFF;

	vcpu->sregs.idt.base  = 0xFBFF000;
	vcpu->sregs.idt.limit = 0x0;

	//memset(&vcpu->sregs.es, 0, sizeof(struct kvm_segment));
	//memset(&vcpu->sregs.fs, 0, sizeof(struct kvm_segment));
	//memset(&vcpu->sregs.gs, 0, sizeof(struct kvm_segment));
	//memset(&vcpu->sregs.tr, 0, sizeof(struct kvm_segment));
	//memset(&vcpu->sregs.ldt, 0, sizeof(struct kvm_segment));

	//memset(&vcpu->sregs.gdt, 0, sizeof(struct kvm_dtable));
	//memset(&vcpu->sregs.idt, 0, sizeof(struct kvm_dtable));

	int err = kvm_vcpu_set_regs(vcpu);
	return err;
}

int kvm_vcpu_singlestep(struct kvm_vcpu *vcpu) {
	struct kvm_guest_debug debug = {
		.control        = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP,
	};

	vcpu->is_debug = 1;
	
	return ioctl(vcpu->fd, KVM_SET_GUEST_DEBUG, &debug);
}

int kvm_vcpu_run(struct kvm_vcpu *vcpu) {
	int err = ioctl(vcpu->fd, KVM_RUN, 0); 
	if (err < 0 && (errno != EINTR && errno != EAGAIN)) {
		return -1;
	}	

	return 0;
}

int kvm_vcpu_loop(struct kvm_vcpu *vcpu) {
	int is_running = 1;
	while(is_running) {
		int err = kvm_vcpu_run(vcpu);
		if(err) {
			break;
		}

		switch(vcpu->run_struct->exit_reason) {
			case KVM_EXIT_FAIL_ENTRY:
				;
				uint64_t code = vcpu->run_struct->fail_entry.hardware_entry_failure_reason;
				fprintf(stderr, "KVM: entry failed, hardware error 0x%lx\n",
					code);
				if (host_supports_vmx() && code == VMX_INVALID_GUEST_STATE) {
					fprintf(stderr,
						"\nIf you're running a guest on an Intel machine without "
						    "unrestricted mode\n"
						"support, the failure can be most likely due to the guest "
						    "entering an invalid\n"
						"state for Intel VT. For example, the guest maybe running "
						    "in big real mode\n"
						"which is not supported on less recent Intel processors."
						    "\n\n");
				}
				is_running = 0;
				break;
			case KVM_EXIT_SHUTDOWN:
				fprintf(stderr, "KVM VCPU did shutdown\n");
				is_running = 0;
				break;
		}

		if(vcpu->is_debug) {
			kvm_vcpu_dump_regs(vcpu);
			kvm_vcpu_dump_code(vcpu);
		}

	}
	return 0;
}

bool host_supports_vmx(void) {
    uint32_t ecx, unused;

    host_cpuid(1, 0, &unused, &unused, &ecx, &unused);
    return ecx & CPUID_EXT_VMX;
}

void host_cpuid(uint32_t function, uint32_t count,
                uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
    uint32_t vec[4];

#ifdef __x86_64__
    asm volatile("cpuid"
                 : "=a"(vec[0]), "=b"(vec[1]),
                   "=c"(vec[2]), "=d"(vec[3])
                 : "0"(function), "c"(count) : "cc");
#else
    asm volatile("pusha \n\t"
                 "cpuid \n\t"
                 "mov %%eax, 0(%2) \n\t"
                 "mov %%ebx, 4(%2) \n\t"
                 "mov %%ecx, 8(%2) \n\t"
                 "mov %%edx, 12(%2) \n\t"
                 "popa"
                 : : "a"(function), "c"(count), "S"(vec)
                 : "memory", "cc");
#endif

    if (eax)
        *eax = vec[0];
    if (ebx)
        *ebx = vec[1];
    if (ecx)
        *ecx = vec[2];
    if (edx)
        *edx = vec[3];
}

void kvm_vcpu_dump_regs(struct kvm_vcpu *vcpu) {
	int err = kvm_vcpu_get_regs(vcpu);
	if(err != 0) {
		printf("WARNING: Could not get VCPU registers\n");
		return;
	}

	printf("\n Registers:\n");
	printf(  " ----------\n");
	printf(" rip: %016llx   rsp: %016llx flags: %016llx\n", 
			vcpu->regs.rip, vcpu->regs.rsp, vcpu->regs.rflags);
	printf(" rax: %016llx   rbx: %016llx   rcx: %016llx\n", 
			vcpu->regs.rax, vcpu->regs.rbx, vcpu->regs.rcx);
	printf(" rdx: %016llx   rsi: %016llx   rdi: %016llx\n", 
			vcpu->regs.rdx, vcpu->regs.rsi, vcpu->regs.rdi);
	printf(" rbp: %016llx    r8: %016llx    r9: %016llx\n", 
			vcpu->regs.rbp, vcpu->regs.r8,  vcpu->regs.r9);
	printf(" r10: %016llx   r11: %016llx   r12: %016llx\n", 
			vcpu->regs.r10, vcpu->regs.r11, vcpu->regs.r12);
	printf(" r13: %016llx   r14: %016llx   r15: %016llx\n", 
			vcpu->regs.r13, vcpu->regs.r14, vcpu->regs.r15);

	printf(" cr0: %016llx   cr2: %016llx   cr3: %016llx\n", vcpu->sregs.cr0, vcpu->sregs.cr2, vcpu->sregs.cr3);
	printf(" cr4: %016llx   cr8: %016llx\n", vcpu->sregs.cr4, vcpu->sregs.cr8);
	printf("\n Segment registers:\n");
	printf(  " ------------------\n");
	printf(" register  selector  base              limit     type  p dpl db s l g avl\n");
	print_segment("cs ", vcpu->sregs.cs);
	print_segment("ss ", vcpu->sregs.ss);
	print_segment("ds ", vcpu->sregs.ds);
	print_segment("es ", vcpu->sregs.es);
	print_segment("fs ", vcpu->sregs.fs);
	print_segment("gs ", vcpu->sregs.gs);
	print_segment("tr ", vcpu->sregs.tr);
	print_segment("ldt", vcpu->sregs.ldt);
	print_dtable("gdt",  vcpu->sregs.gdt);
	print_dtable("idt",  vcpu->sregs.idt);

	printf("\n APIC:\n");
	printf(  " -----\n");
	printf(" efer: %016lx  apic base: %016lx  nmi: TODO\n",
	       (uint64_t) vcpu->sregs.efer, (uint64_t) vcpu->sregs.apic_base
	       );

	printf("\n Interrupt bitmap:\n");
	printf(  " -----------------\n");
	for (int i = 0; i < (KVM_NR_INTERRUPTS + 63) / 64; i++)
		printf(" %016lx", (uint64_t) vcpu->sregs.interrupt_bitmap[i]);
	printf("\n");

	return;
}

void kvm_vcpu_dump_code(struct kvm_vcpu *vcpu) {
	int err = kvm_vcpu_get_next_code_byte(vcpu);
	if(err) {
		return;
	}
	printf("\n Code:\n");
	printf(  " -----------------\n");
	while(ud_disassemble(&vcpu->ud_obj)) {
		printf("%s\n", ud_insn_asm(&vcpu->ud_obj));
	}
	printf(  " -----------------\n");

	return;
}

int kvm_vcpu_get_next_code_byte(struct kvm_vcpu *vcpu) {
	int err = kvm_vcpu_get_regs(vcpu);
	if(err != 0) {
		return err;
	}

	void *host_p = kvm_pager_get_host_p(&vcpu->vm->pager, vcpu->regs.rip);
	size_t disassembly_size = 40;
	ud_set_input_buffer(&vcpu->ud_obj, (char *)host_p, disassembly_size);

	return 0;
}

