SET( libelkvm_MOC_HEADERS
  config.h
  elkvm.h
  gdt.h
  heap.h
  idt.h
  kvm.h
  mapping.h
  mem_chunk.h
  pager.h
  region_manager.h
  stack.h
  types.h
  syscall.h
  tss.h
  vcpu.h
  )

install (FILES elkvm.h
  config.h
  kvm.h
  pager.h
  stack.h
  types.h
  vcpu.h
  DESTINATION include/elkvm)
