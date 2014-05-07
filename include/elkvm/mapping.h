#pragma once

#include <elkvm.h>

struct region_mapping *elkvm_mapping_alloc();
struct region_mapping *elkvm_mapping_find(struct kvm_vm *vm, void *host_p);
bool address_in_mapping(struct region_mapping *mapping, void *host_p);

