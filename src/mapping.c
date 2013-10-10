#include <elkvm.h>
#include <list.h>
#include <mapping.h>

struct region_mapping *elkvm_mapping_alloc() {
  struct region_mapping *mapping = malloc(sizeof(struct region_mapping));
  if(mapping == NULL) {
    return NULL;
  }

  memset(mapping, 0, sizeof(mapping));
  return mapping;
}

struct region_mapping *elkvm_mapping_find(struct kvm_vm *vm, void *host_p) {
  struct region_mapping *mapping;

  list_each(vm->mappings, elem) {
    if(address_in_mapping(elem, host_p)) {
      mapping = elem;
    }
  }

  return mapping;
}

bool address_in_mapping(struct region_mapping *mapping, void *host_p) {
  return (mapping->host_p <= host_p) &&
    (host_p < (mapping->host_p + mapping->length));
}
