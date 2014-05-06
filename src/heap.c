#include <errno.h>

#include <elkvm.h>
#include <heap.h>
#include <region.h>

int elkvm_heap_initialize(struct kvm_vm *vm, struct elkvm_memory_region *region,
    uint64_t size) {
  assert(region != NULL);

  uint64_t data_end = region->guest_virtual + size;
  list_push_front(vm->heap, region);
  assert(list_length(vm->heap) ==  1);

  int err = kvm_pager_set_brk(&vm->pager, data_end);
  if(err) {
    return err;
  }

  uint64_t brk = next_page(data_end);
  if(brk != data_end) {
    err = elkvm_brk(vm, brk);
    if(err) {
      return err;
    }
  }

  return 0;
}

int elkvm_heap_grow(struct kvm_vm *vm, uint64_t size) {
  struct elkvm_memory_region *region = elkvm_region_create(vm, size);
  if(region == NULL) {
    /* guest is completely out of memory */
    return -ENOMEM;
  }
  list_push_front(vm->heap, region);

  return 0;
}

int elkvm_brk(struct kvm_vm *vm, uint64_t newbrk) {
  int err;

  if(elkvm_within_current_heap_region(vm, newbrk)) {
    err = elkvm_brk_nogrow(vm, newbrk);
  } else {
    uint64_t tmpbrk = elkvm_last_heap_address(vm);
    err = elkvm_brk_nogrow(vm, tmpbrk);
    vm->pager.brk_addr = tmpbrk;
    assert(err == 0);
    err = elkvm_brk_grow(vm, newbrk);
  }

  if(err) {
    return err;
  }

  vm->pager.brk_addr = newbrk;
  return 0;
}

int elkvm_brk_nogrow(struct kvm_vm *vm, uint64_t newbrk) {
  struct elkvm_memory_region **heap = list_elem_front(vm->heap);
  uint64_t oldbrk_region_base = (*heap)->guest_virtual;
  assert(vm->pager.brk_addr >= oldbrk_region_base);
  uint64_t newbrk_offset = 0x0;
  if(page_aligned(vm->pager.brk_addr)) {
    newbrk_offset = vm->pager.brk_addr - oldbrk_region_base;
  } else {
    newbrk_offset = next_page(vm->pager.brk_addr - oldbrk_region_base);
  }

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
  struct elkvm_memory_region *heap_top = *list_elem_front(vm->heap);
  while(newbrk < heap_top->guest_virtual) {
    list_pop_front(vm->heap);
    elkvm_region_free(vm, heap_top);
    heap_top = *list_elem_front(vm->heap);
  }

  guestptr_t unmap_addr = page_aligned(vm->pager.brk_addr) ?
    vm->pager.brk_addr - ELKVM_PAGESIZE : vm->pager.brk_addr;
  guestptr_t unmap_end = page_aligned(newbrk) ? newbrk :
    next_page(newbrk);
  for(uint64_t guest_addr = unmap_addr;
      guest_addr >= unmap_end;
      guest_addr -= ELKVM_PAGESIZE) {
    int err = kvm_pager_destroy_mapping(&vm->pager, guest_addr);
    if(err) {
      return err;
    }
  }

  vm->pager.brk_addr = newbrk;
  return 0;
}

int elkvm_brk_map(struct kvm_vm *vm, uint64_t newbrk, uint64_t off) {
  uint64_t map_addr = next_page(vm->pager.brk_addr);
  struct elkvm_memory_region **heap_top = list_elem_front(vm->heap);
  void *host_p = (*heap_top)->host_base_p + off;
  if((*heap_top)->guest_virtual == 0x0) {
    (*heap_top)->guest_virtual = map_addr;
  }
  while(map_addr <= newbrk) {
    int err = kvm_pager_create_mapping(&vm->pager, host_p, map_addr, PT_OPT_WRITE);
    if(err) {
      return err;
    }
    map_addr = map_addr + ELKVM_PAGESIZE;
    host_p = host_p + ELKVM_PAGESIZE;
    assert(host_p <= ((*heap_top)->host_base_p + (*heap_top)->region_size));
  }

  return 0;
}
