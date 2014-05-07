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
  region.h
  stack.h
  syscall.h
  tss.h
  vcpu.h
  )

install (FILES elkvm.h DESTINATION include)
