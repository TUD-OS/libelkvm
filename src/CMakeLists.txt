SET( libelkvm_SRCS
  debug.c
  elfloader.c
  gdbstub.c
  gdt.c
  heap.c
  idt.c
  mapping.c
  pager.c
  region.c
  signal.c
  stack.c
  syscall.c
  tss.c
  vcpu.c
  vm.c
  )
ADD_LIBRARY( elkvm SHARED ${libelkvm_SRCS} )
target_link_libraries (elkvm check)
target_link_libraries (elkvm udis86)

install (TARGETS elkvm DESTINATION lib)
