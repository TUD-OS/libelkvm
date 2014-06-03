SET( libelkvm_SRCS
  debug.c
  elfloader.c
  gdbstub.c
  gdt.c
  heap.c
  idt.c
  list/list.c
  mapping.c
  pager.c
  region.cc
  region_manager.cc
  signal.c
  stack.c
  syscall.cc
  tss.c
  vcpu.c
  vm.c
  )
ADD_LIBRARY( elkvm SHARED ${libelkvm_SRCS} )
target_link_libraries (elkvm udis86)
target_link_libraries (elkvm elf)
add_dependencies(elkvm entry)
add_dependencies(elkvm isr)
add_dependencies(elkvm signal)

install (TARGETS elkvm DESTINATION lib)
