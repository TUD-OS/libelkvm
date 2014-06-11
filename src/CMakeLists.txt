SET( libelkvm_SRCS
  debug.c
  elfloader.c
  environ.cc
  gdbstub.c
  gdt.c
  heap.cc
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

if(LIBUDIS86_FOUND)
  target_link_libraries (elkvm udis86)
endif(LIBUDIS86_FOUND)

target_link_libraries (elkvm elf)
add_dependencies(elkvm entry)
add_dependencies(elkvm isr)
add_dependencies(elkvm signal)

install (TARGETS elkvm DESTINATION lib)
