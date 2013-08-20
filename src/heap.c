#include <elkvm.h>
#include <heap.h>
#include <region.h>

int elkvm_heap_initialize(struct kvm_vm *vm, struct elkvm_memory_region *region,
    uint64_t size) {
  vm->heap = malloc(sizeof(struct elkvm_memory_region_list));
	vm->heap->data = region;
  vm->heap->next = NULL;
  int err = kvm_pager_set_brk(&vm->pager, region->guest_virtual + size);
  return err;
}

int elkvm_heap_grow(struct kvm_vm *vm, uint64_t size) {
  struct elkvm_memory_region_list *newtop;
  newtop = malloc(sizeof(struct elkvm_memory_region_list));
  newtop->next = vm->heap;
  newtop->data = elkvm_region_create(vm, size);
  if(newtop->data == NULL) {
    /* guest is out of memory, try and get some new mem */
  }
  vm->heap = newtop;
  return 0;
}

int elkvm_brk(struct kvm_vm *vm, uint64_t newbrk) {
  uint64_t brksize = newbrk - vm->pager.brk_addr;
}

int elkvm_brk_nogrow(struct kvm_vm *vm, uint64_t newbrk) {
  vm->pager.brk_addr = newbrk;
  /* TODO check if new mappings need to be created */
  return -1;
}

int elkvm_brk_grow(struct kvm_vm *vm) {
  return -1;
}
