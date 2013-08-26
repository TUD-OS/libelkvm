_start:
  pushq %rax
  pushq $1
  vmcall
  sysretq
