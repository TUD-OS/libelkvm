SET( libelkvm_SRCS
  debug.cc
  elfloader.cc
  environ.cc
  gdbstub.cc
  gdt.cc
  heap.cc
  idt.cc
  interrupt.cc
  kvm.cc
  mapping.cc
  mprotect.cc
  pager.cc
  region.cc
  region_manager.cc
  signal.cc
  stack.cc
  syscall.cc
  syscall_default.cc
  tss.cc
  udis86.cc
  vcpu.cc
  vm.cc
  vm_internals.cc
  )
ADD_LIBRARY( elkvm SHARED ${libelkvm_SRCS} )

if(LIBUDIS86_FOUND)
  # BD: Weird. According to the documentation, passing an absolute library
  #     path, such as ${LIBUDIS86_LIBRARIES} should instruct CMake to write
  #     -l<absolute path name>. However, in my case it only generated -ludis86
  #     and forgot about the search path. Therefore, we extract the path here
  #     separately and pass it as an explicit argument for udis86 dir.
  get_filename_component(LIBUDIS86_DIR "${LIBUDIS86_LIBRARIES}" PATH)
  target_link_libraries (elkvm -L${LIBUDIS86_DIR} ${LIBUDIS86_LIBRARIES})
endif(LIBUDIS86_FOUND)

target_link_libraries (elkvm elf)
add_dependencies(elkvm entry)
add_dependencies(elkvm isr)
add_dependencies(elkvm signal)

install (TARGETS elkvm DESTINATION lib)
