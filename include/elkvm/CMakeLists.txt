SET( libelkvm_MOC_HEADERS
  elkvm-signal.h
  elkvm.h
  gdt.h
  heap.h
  idt.h
  kvm.h
  list.h
  mapping.h
  mem_chunk.h
  pager.h
  region-c.h
  stack.h
  syscall.h
  tss.h
  vcpu.h
  )

install (FILES elkvm.h
  elkvm-signal.h
  list.h
  kvm.h
  pager.h
  region-c.h
  vcpu.h
  DESTINATION include/elkvm)
