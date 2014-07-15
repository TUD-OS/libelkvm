SET( libelkvm_MOC_HEADERS
  config.h
  elkvm-signal.h
  elkvm.h
  gdt.h
  heap.h
  idt.h
  kvm.h
  mapping.h
  mem_chunk.h
  pager.h
  stack.h
  syscall.h
  tss.h
  vcpu.h
  )

install (FILES elkvm.h
  config.h
  elkvm-signal.h
  kvm.h
  pager.h
  stack.h
  vcpu.h
  DESTINATION include/elkvm)
