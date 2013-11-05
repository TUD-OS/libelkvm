#include <errno.h>

#include <elkvm.h>
#include <heap.h>
#include <region.h>

int elkvm_heap_initialize(struct kvm_vm *vm, struct elkvm_memory_region *region,
    uint64_t size) {
  vm->heap = malloc(sizeof(struct elkvm_memory_region_list));
	vm->heap->data = region;
  vm->heap->next = NULL;
  uint64_t data_end = region->guest_virtual + size;

  int err = kvm_pager_set_brk(&vm->pager, data_end);
  if(err) {
    return err;
  }

  uint64_t brk = (data_end + 0x1000) & ~0xFFF;
  if(brk != data_end) {
    err = elkvm_brk(vm, brk);
    if(err) {
      return err;
    }
  }

  return 0;
}

int elkvm_heap_grow(struct kvm_vm *vm, uint64_t size) {
  struct elkvm_memory_region_list *newtop;
  newtop = malloc(sizeof(struct elkvm_memory_region_list));
  assert(newtop != NULL);

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
    err = elkvm_brk_nogrow(vm, newbrk);
  } else {
    err = elkvm_brk_grow(vm, newbrk);
  }

  if(err) {
    return err;
  }

  vm->pager.brk_addr = newbrk;
  return 0;
}

int elkvm_brk_nogrow(struct kvm_vm *vm, uint64_t newbrk) {
  assert(vm->pager.brk_addr >= vm->heap->data->guest_virtual);
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

int elkvm_brk_shrink(struct kvm_vm *vm, uint64_t newbrk) {
    for(uint64_t guest_addr = vm->pager.brk_addr;
        guest_addr >= next_page(newbrk);
        guest_addr -= 0x1000) {
      int err = kvm_pager_destroy_mapping(&vm->pager, guest_addr);
      if(err) {
        return err;
      }
    }

    vm->pager.brk_addr = newbrk;
    return 0;
}

int elkvm_brk_map(struct kvm_vm *vm, uint64_t newbrk, uint64_t off) {
  uint64_t map_addr = (vm->pager.brk_addr & ~0xFFF) + 0x1000;

  void *host_p = vm->heap->data->host_base_p + off;
  if(vm->heap->data->guest_virtual == 0x0) {
    vm->heap->data->guest_virtual = map_addr;
  }
  while(map_addr <= newbrk) {
    int err = kvm_pager_create_mapping(&vm->pager, host_p, map_addr, 1, 0);
    if(err) {
      return err;
    }
    map_addr = map_addr + 0x1000;
    host_p = host_p + 0x1000;
  }

  return 0;
}
