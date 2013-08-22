#include <errno.h>

#include <elkvm.h>
#include <heap.h>
#include <region.h>

int elkvm_heap_initialize(struct kvm_vm *vm, struct elkvm_memory_region *region,
    uint64_t size) {
  vm->heap = malloc(sizeof(struct elkvm_memory_region_list));
	vm->heap->data = region;
  vm->heap->next = NULL;
  printf("SETTING brk to: 0x%lx\n", region->guest_virtual + size);
  int err = kvm_pager_set_brk(&vm->pager, region->guest_virtual + size);
  return err;
}

int elkvm_heap_grow(struct kvm_vm *vm, uint64_t size) {
  struct elkvm_memory_region_list *newtop;
  newtop = malloc(sizeof(struct elkvm_memory_region_list));
  newtop->next = vm->heap;
  newtop->data = elkvm_region_create(vm, size);
  if(newtop->data == NULL) {
    /* guest is completely out of memory */
    return -ENOMEM;
  }
  vm->heap = newtop;
  return 0;
}

int elkvm_brk(struct kvm_vm *vm, uint64_t newbrk) {
  int err;

  if(elkvm_within_current_heap_region(vm, newbrk)) {
    printf("new brk (0x%lx) is larger than oldbrk (0x%lx), "
        "but fits in region: 0x%lx (0x%lx)\n",
        newbrk, vm->pager.brk_addr,
        vm->heap->data->guest_virtual, vm->heap->data->region_size);
    err = elkvm_brk_nogrow(vm, newbrk);
  } else {
    printf("new brk (0x%lx) does not fit in region 0x%lx (0x%lx)\n",
        newbrk, vm->heap->data->guest_virtual, vm->heap->data->region_size);
    err = elkvm_brk_grow(vm, newbrk);
  }

  if(err) {
    return err;
  }

  vm->pager.brk_addr = newbrk;
  return 0;
}

int elkvm_brk_nogrow(struct kvm_vm *vm, uint64_t newbrk) {
  uint64_t newbrk_offset = ((vm->pager.brk_addr - vm->heap->data->guest_virtual)
    & ~0xFFF)
    + 0x1000;
  int err = elkvm_brk_map(vm, newbrk, newbrk_offset);
  if(err) {
    return err;
  }

  return 0;
}

int elkvm_brk_grow(struct kvm_vm *vm, uint64_t newbrk) {
  uint64_t size = newbrk - vm->pager.brk_addr;
  int err = elkvm_heap_grow(vm, size);
  if(err) {
    return err;
  }

  err = elkvm_brk_map(vm, newbrk, 0);
  if(err) {
    return err;
  }

  return 0;
}

int elkvm_brk_map(struct kvm_vm *vm, uint64_t newbrk, uint64_t off) {
  uint64_t size = newbrk - vm->pager.brk_addr;
  uint64_t guest = (vm->pager.brk_addr & ~0xFFF) + 0x1000;

  void *host_p = vm->heap->data->host_base_p + off;
  if(vm->heap->data->guest_virtual == 0x0) {
    vm->heap->data->guest_virtual = guest;
  }
  for( ; size > 0x1000; size = size - 0x1000) {
    printf("CREATE MAPPING for BRK from 0x%lx to %p size left: 0x%lx\n",
        guest, host_p, size);
    int err = kvm_pager_create_mapping(&vm->pager, host_p, guest, 1, 0);
    if(err) {
      return err;
    }
    guest = guest + 0x1000;
    host_p = host_p + 0x1000;
  }

  return 0;
}
