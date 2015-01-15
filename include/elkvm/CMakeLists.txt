SET( libelkvm_MOC_HEADERS
    config.h
    debug.h
    elfloader.h
    elkvm.h
    elkvm-internal.h
    elkvm-log.h
    elkvm-udis86.h
    environ.h
    gdbstub.h
    gdt.h
    heap.h
    idt.h
    interrupt.h
    kvm.h
    mapping.h
    pager.h
    region.h
    region_manager.h
    regs.h
    stack.h
    syscall.h
    tss.h
    types.h
    vcpu.h
)

install (FILES 
  ${libelkvm_MOC_HEADERS}
  DESTINATION include/elkvm)
