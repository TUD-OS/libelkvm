#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <elkvm.h>
#include <pager.h>
#include <stack.h>
#include <vcpu.h>

int elkvm_pager_initialize(struct kvm_vm *vm, int mode) {
	if(vm->fd < 1) {
		return -EIO;
	}

	struct elkvm_memory_region *pts_region = elkvm_region_create(vm, ELKVM_PAGER_MEMSIZE);
	if(pts_region == NULL) {
		return -ENOMEM;
	}

	vm->pager.mode = mode;
	vm->pager.other_chunks = NULL;

	vm->pager.host_pml4_p = pts_region->host_base_p;
	uint64_t pml4_guest_physical = host_to_guest_physical(&vm->pager,
			pts_region->host_base_p);
	vm->pager.guest_next_free = KERNEL_SPACE_BOTTOM;

	int err = elkvm_pager_create_page_tables(&vm->pager, mode);
	if(err) {
		return err;
	}

	err = kvm_vcpu_set_cr3(vm->vcpus->vcpu, pml4_guest_physical);
	if(err) {
		return err;
	}

  vm->pager.free_slot_id = -1;
  for(int i = 0; i < KVM_MEMORY_SLOTS; i++) {
    vm->pager.free_slot[i] = 0;
  }

  vm->pager.vm = vm;

	return 0;
}

struct kvm_userspace_memory_region *elkvm_pager_alloc_chunk(struct kvm_pager *pager,
    void *addr, uint64_t chunk_size, int flags) {
  struct kvm_userspace_memory_region *chunk;
  chunk = malloc(sizeof(struct kvm_userspace_memory_region));
  if(chunk == NULL) {
    return NULL;
  }

	chunk->userspace_addr = (__u64)addr;
  chunk->guest_phys_addr = pager->total_memsz;
	chunk->memory_size = chunk_size;
	chunk->flags = flags;
  pager->total_memsz = pager->total_memsz + chunk_size;

	int chunk_count = elkvm_pager_append_mem_chunk(pager, chunk);
	if(chunk_count < 0) {
    free(chunk);
    return NULL;
	}
  if(pager->free_slot_id >= 0) {
    chunk->slot = pager->free_slot[pager->free_slot_id];
    pager->free_slot_id--;
  } else {
  	/* system chunk has slot 0, so we need to add 1 to all user chunks */
  	chunk->slot = chunk_count + 1;
  }

  return chunk;
}

int elkvm_pager_create_mem_chunk(struct kvm_pager *pager, void **chunk_host_p,
    int chunk_size) {

	if(pager == NULL) {
    *chunk_host_p = NULL;
		return -EIO;
	}

	/* keep sizes page aligned */
	if((chunk_size & ~0xFFF) != chunk_size) {
		return -EIO;
	}

	int err = posix_memalign(chunk_host_p, HOST_PAGESIZE, chunk_size);
	if(err) {
		return err;
	}
  struct kvm_userspace_memory_region *chunk =
    elkvm_pager_alloc_chunk(pager, *chunk_host_p, chunk_size, 0);
  if(chunk == NULL) {
    free(*chunk_host_p);
    *chunk_host_p = NULL;
    return -ENOMEM;
  }

  err = elkvm_pager_map_chunk(pager->vm, chunk);
	return err;
}

int elkvm_pager_map_chunk(struct kvm_vm *vm, struct kvm_userspace_memory_region *chunk) {
  if(chunk->memory_size == 0) {
    vm->pager.free_slot_id++;
    assert(vm->pager.free_slot_id < KVM_MEMORY_SLOTS);
    vm->pager.free_slot[vm->pager.free_slot_id] = chunk->slot;
  }

  assert(chunk->slot < KVM_MEMORY_SLOTS);
	int err = ioctl(vm->fd, KVM_SET_USER_MEMORY_REGION, chunk);
  return err ? -errno : 0;
//	if(err) {
//		long sz = sysconf(_SC_PAGESIZE);
//		printf("Could not set memory region\n");
//		printf("Error No: %i Msg: %s\n", errno, strerror(errno));
//		printf("Pagesize is: %li\n", sz);
//		printf("Here are some sanity checks that are applied in kernel:\n");
//		int ms = chunk->memory_size & (sz-1);
//		int pa = chunk->guest_phys_addr & (sz-1);
//		int ua = chunk->userspace_addr & (sz-1);
//		printf("memory_size & (PAGE_SIZE -1): %i\n", ms);
//		printf("guest_phys_addr & (PAGE_SIZE-1): %i\n", pa);
//		printf("userspace_addr & (PAGE_SIZE-1): %i\n", ua);
//		printf("TODO verify write access\n");
//    return -errno;
//	}
//	return 0;
}

int elkvm_pager_append_mem_chunk(struct kvm_pager *pager,
		struct kvm_userspace_memory_region *chunk) {
  list_push(pager->other_chunks, chunk);
  return list_length(pager->other_chunks);
}

int elkvm_pager_chunk_count(struct kvm_pager *pager) {
  return list_length(pager->other_chunks);
}

int elkvm_pager_free_chunk(struct kvm_pager *pager,
    struct kvm_userspace_memory_region *chunk) {
  assert(pager != NULL);
  assert(chunk != NULL);
  assert(chunk != &pager->system_chunk);

  list_remove(pager->other_chunks, chunk);
  return 0;
}

struct kvm_userspace_memory_region
elkvm_pager_get_system_chunk(struct kvm_pager *pager) {
  return pager->system_chunk;
}

struct kvm_userspace_memory_region *
elkvm_pager_get_chunk(struct kvm_pager *pager, int c) {
  int i = 0;
  list_each(pager->other_chunks, chunk) {
    if(i == c) {
      return chunk;
    }
    i++;
  }

  return NULL;
}

int elkvm_pager_create_page_tables(struct kvm_pager *pager, int mode) {
	if(pager == NULL ||  pager->host_pml4_p == NULL) {
		return -EINVAL;
	}
	if(mode != PAGER_MODE_X86_64) {
		return -ENOSYS;
	}

	if(pager->system_chunk.memory_size < 0x400000) {
		return -1;
	}

	memset(pager->host_pml4_p, 0, 0x400000);
	pager->host_next_free_tbl_p = pager->host_pml4_p + HOST_PAGESIZE;

	return 0;
}

struct kvm_userspace_memory_region *
	elkvm_pager_find_region_for_host_p(struct kvm_pager *pager, void *host_mem_p) {
    if(address_in_region(&pager->system_chunk, host_mem_p)) {
			return &pager->system_chunk;
		}

    list_each(pager->other_chunks, region) {
      assert(region != NULL);

      if(address_in_region(region, host_mem_p)) {
				return region;
			}
		}

		return NULL;
}

uint64_t elkvm_pager_map_kernel_page(struct kvm_pager *pager, void *host_mem_p,
		int writeable, int executable) {

	uint64_t guest_physical = host_to_guest_physical(pager, host_mem_p);
	uint64_t guest_virtual = (pager->guest_next_free & ~(ELKVM_PAGESIZE-1)) | (guest_physical & (ELKVM_PAGESIZE-1));
  assert(guest_virtual != 0);

  ptopt_t opts = 0;
  if(writeable) {
    opts |= PT_OPT_WRITE;
  }
  if(executable) {
    opts |= PT_OPT_EXEC;
  }

	uint64_t *pt_entry = elkvm_pager_page_table_walk(pager, guest_virtual, opts, 1);
	if(pt_entry == NULL) {
		return -EIO;
	}

	while(entry_exists(pt_entry)) {
		pt_entry++;
		guest_virtual = guest_virtual + ELKVM_PAGESIZE;
		if(((uint64_t)pt_entry & ~(ELKVM_PAGESIZE-1)) == (uint64_t)pt_entry) {
			/*this page table seems to be completely full, try the next one */
			guest_virtual = guest_virtual + 0x100000;
      assert(guest_virtual != 0);
			pt_entry = elkvm_pager_page_table_walk(pager, guest_virtual, opts, 1);
		}
	}

  /*
   * TODO setting this page up for user makes interrupts work,
   * fix this!
   */
	int err = elkvm_pager_create_entry(pager, pt_entry, guest_physical, opts);
  if(err) {
    return err;
  }

	return guest_virtual;
}

/*
 * XXX this will fail for mappings that are larger than what fits
 * into offset in pd * 512 pages
 */
int elkvm_pager_unmap_region(struct kvm_pager *pager, uint64_t guest_start_addr,
    unsigned pages) {

  uint64_t guest_addr = guest_start_addr;

  /* get the base address of pt for first guest addr */
  uint64_t guest_pt_base_addr = guest_addr & ~0x1FFFFF;
  /* calc offset in that pt */
  off_t offset = (guest_addr & 0x1FF000) >> 12;
  /* calc amount of pages left in that pt */
  unsigned pages_remaining = 512 - offset;

  while(pages) {
    uint64_t *pt_entry = elkvm_pager_page_table_walk(pager, guest_addr, 0, 0);

    /* map those pages */
    while(pages && pages_remaining) {
      *pt_entry = 0;

      pt_entry++;
      pages_remaining--;
      pages--;
    }
    /* do again for next pt now we have 512 pages room */
    guest_addr = guest_pt_base_addr + 0x200000;
    guest_pt_base_addr += 0x200000;
    pages_remaining = 512;
    offset = 0;
  }


  return 0;
}
/*
 * XXX this will fail for mappings that are larger than what fits
 * into offset in pd * 512 pages
 */
int elkvm_pager_map_region(struct kvm_pager *pager, void *host_start_p,
    uint64_t guest_start_addr, unsigned pages, ptopt_t opts) {

  uint64_t guest_addr = guest_start_addr;
	uint64_t guest_physical = host_to_guest_physical(pager, host_start_p);

  /* get the base address of pt for first guest addr */
  uint64_t guest_pt_base_addr = guest_addr & ~0x1FFFFF;
  /* calc offset in that pt */
  off_t offset = (guest_addr & 0x1FF000) >> 12;
  /* calc amount of pages left in that pt */
  assert(offset <= 512);
  unsigned pages_remaining = 512 - offset;

  assert(pages < (512*512));
  while(pages) {
    uint64_t *pt_base = elkvm_pager_page_table_walk(pager, guest_pt_base_addr, opts, 1);
    uint64_t *pt_entry = pt_base + offset;

    /* map those pages */
    while(pages && pages_remaining) {
      int err = elkvm_pager_create_entry(pager, pt_entry, guest_physical, opts);
      assert(err == 0);

      pt_entry++;
      guest_physical+=ELKVM_PAGESIZE;
      pages_remaining--;
      pages--;
    }
    /* do again for next pt now we have 512 pages room */
    guest_pt_base_addr += 0x200000;
    pages_remaining = 512;
    offset = 0;
  }


  return 0;
}

int elkvm_pager_create_mapping(struct kvm_pager *pager, void *host_mem_p,
		uint64_t guest_virtual, ptopt_t opts) {
	int err;
  assert(guest_virtual != 0);

	assert(pager->system_chunk.userspace_addr != 0);
	assert((host_mem_p < pager->host_pml4_p) ||
			host_mem_p >= (pager->host_pml4_p + 0x400000));

	/* sanity checks on the host, we need 4MB to fit all possible page maps */
	if(pager->system_chunk.memory_size < ELKVM_SYSTEM_MEMSIZE) {
		return -EIO;
	}

	/* sanity checks on the offset */
	if(((uint64_t)host_mem_p & 0xFFF) != (guest_virtual & 0xFFF)) {
		return -EIO;
	}

	uint64_t guest_physical = host_to_guest_physical(pager, host_mem_p);
  assert(guest_physical != 0);

	uint64_t *pt_entry = elkvm_pager_page_table_walk(pager, guest_virtual, opts, 1);
  assert(pt_entry != NULL && "pt entry must not be NULL after page table walk");

	/* do NOT overwrite existing page table entries! */
	if(entry_exists(pt_entry)) {
		if((*pt_entry & ~(ELKVM_PAGESIZE-1)) != (guest_physical & ~(ELKVM_PAGESIZE-1))) {
			return -1;
		}
		/* TODO check if flags are the same */
		return 0;
	}

	err = elkvm_pager_create_entry(pager, pt_entry, guest_physical, opts);

	return err;
}

int elkvm_pager_destroy_mapping(struct kvm_pager *pager, uint64_t guest_virtual) {
	uint64_t *pt_entry = elkvm_pager_page_table_walk(pager, guest_virtual,
			0, 0);

  if(pt_entry == NULL) {
    return -1;
  }

  *pt_entry = 0;
  return 0;
}

void *elkvm_pager_get_host_p(struct kvm_pager *pager, uint64_t guest_virtual) {
  assert(guest_virtual != 0);
	uint64_t *entry = elkvm_pager_page_table_walk(pager, guest_virtual, 0, 0);
	if(entry == NULL) {
		return NULL;
	}

  struct kvm_userspace_memory_region *chunk = NULL;
  uint64_t guest_physical = (*entry & 0x000FFFFFFFFFF000) | (guest_virtual & (ELKVM_PAGESIZE-1));
  if(guest_address_in_region(&pager->system_chunk, guest_physical)) {
    chunk = &pager->system_chunk;
  } else {
    list_each(pager->other_chunks, c) {
      if(guest_address_in_region(c, guest_physical)) {
        chunk = c;
      }
    }
  }
	return (void *)((guest_physical - chunk->guest_phys_addr) + chunk->userspace_addr);
}

uint64_t *elkvm_pager_page_table_walk(struct kvm_pager *pager, uint64_t guest_virtual,
		ptopt_t opts, int create) {
  assert(guest_virtual != 0);

	uint64_t *table_base = (uint64_t *)pager->host_pml4_p;
	/* we should always have paging in place, when this gets called! */
	assert(table_base != NULL);

	uint64_t *entry = NULL;
	int addr_low = 39;
	int addr_high = 47;

	for(int i = 0; i < 3; i++) {
		entry = elkvm_pager_find_table_entry(pager, table_base,
				guest_virtual, addr_low, addr_high);
		addr_low -= 9;
		addr_high -= 9;
    if(create) {
      if(!entry_exists(entry)) {
				int err = elkvm_pager_create_table(pager, entry, opts);
				if(err) {
					return NULL;
				}
      }
      if(opts & PT_OPT_WRITE) {
				*entry |= PT_BIT_WRITEABLE;
			}
      if(opts & PT_OPT_EXEC) {
				*entry &= ~PT_BIT_NXE;
			}
		}
    if(!entry_exists(entry)) {
      return NULL;
    }
		table_base = elkvm_pager_find_next_table(pager, entry);
	}

	entry = elkvm_pager_find_table_entry(pager, table_base,
			guest_virtual, addr_low, addr_high);
	addr_low -= 9;
	addr_high -= 9;
	if(!entry_exists(entry) && !create) {
    return NULL;
  }

	return entry;
}

uint64_t *elkvm_pager_find_next_table(struct kvm_pager *pager,
		uint64_t *host_tbl_entry_p) {
	if(!entry_exists(host_tbl_entry_p)) {
		return NULL;
	}

	/* location of the next table is in bits 12 - 51 of the entry */
	uint64_t guest_next_tbl = *host_tbl_entry_p & 0x000FFFFFFFFFF000;
	return (uint64_t *)(pager->system_chunk.userspace_addr + guest_next_tbl);
}

uint64_t *elkvm_pager_find_table_entry(struct kvm_pager *pager,
		uint64_t *host_tbl_base_p, uint64_t guest_virtual, int off_low, int off_high) {
	uint64_t off = (guest_virtual << (63 - off_high)) >> ((63 - off_high) + off_low);

	uint64_t *entry = host_tbl_base_p + off;
	return entry;
}

int elkvm_pager_create_table(struct kvm_pager *pager, uint64_t *host_entry_p,
    ptopt_t opts) {

	uint64_t guest_next_tbl = host_to_guest_physical(pager, pager->host_next_free_tbl_p);
	if(guest_next_tbl == 0) {
		return -EIO;
	}
	memset(pager->host_next_free_tbl_p, 0, HOST_PAGESIZE);
	pager->host_next_free_tbl_p += HOST_PAGESIZE;

	return elkvm_pager_create_entry(pager, host_entry_p, guest_next_tbl, opts);
}

int elkvm_pager_create_entry(struct kvm_pager *pager, uint64_t *host_entry_p,
		uint64_t guest_next, ptopt_t opts) {
	/* save base address of next tbl in entry */
	*host_entry_p = page_begin(guest_next);

	*host_entry_p |= PT_BIT_USER;

	if(opts & PT_OPT_WRITE) {
		*host_entry_p |= PT_BIT_WRITEABLE;
	}

	if(!(opts & PT_OPT_EXEC)) {
		*host_entry_p |= PT_BIT_NXE;
	}

	/* mark the entry as present */
	*host_entry_p |= PT_BIT_PRESENT;

	return 0;
}

int elkvm_pager_set_brk(struct kvm_pager *pager, uint64_t guest_addr) {
  pager->brk_addr = guest_addr;
  return 0;
}

int elkvm_pager_handle_pagefault(struct kvm_pager *pager, uint64_t pfla,
    uint32_t err_code) {

    struct kvm_vcpu *vcpu = elkvm_vcpu_get(pager->vm, 0);
		void *host_p = elkvm_pager_get_host_p(pager, pfla);

    if(pager->vm->debug) {
      printf("PFLA: 0x%lx\nCURRENT STACK TOP:0x%lx\n",
          pfla, pager->vm->current_user_stack->guest_virtual);
    }
    if(is_stack_expansion(pager->vm, vcpu, pfla)) {
      int err = expand_stack(pager->vm, vcpu);
      if(pager->vm->debug) {
        elkvm_pager_dump_page_fault_info(pager, pfla, err_code, host_p);
      }
      if(err) {
        elkvm_pager_dump_page_tables(pager);
        return err;
      }
      return 0;
    }
    elkvm_pager_dump_page_fault_info(pager, pfla, err_code, host_p);
		if(host_p != NULL) {
			elkvm_pager_dump_page_tables(pager);
		}

    return 1;
}

void elkvm_pager_dump_page_fault_info(struct kvm_pager *pager, uint64_t pfla,
    uint32_t err_code, void *host_p) {
		printf(" Page Fault:\n");
		printf(" -------------------\n");
		printf(" PFLA: 0x%016lx, expected host address: %p\n", pfla, host_p);
		uint64_t page_off = pfla & (ELKVM_PAGESIZE-1);
		uint64_t pt_off   = (pfla >> 12) & 0x1FF;
		uint64_t pd_off   = (pfla >> 21) & 0x1FF;
		uint64_t pdpt_off = (pfla >> 30) & 0x1FF;
		uint64_t pml4_off = (pfla >> 39) & 0x1FF;
		printf(" Offsets: PML4: %3lu PDPT: %3lu PD: %3lu PT: %3lu Page: %4lu\n",
				pml4_off, pdpt_off, pd_off, pt_off, page_off);

    if(err_code >= 0) {
      printf("\n");
      printf(" Page Fault Error Code:\n");
      printf(" ----------------------\n");
      printf(" P: %1x R/W: %1x U/S: %1x RSV: %1x I/D: %1x\n",
          err_code & 0x1,
          (err_code >> 1) & 0x1,
          (err_code >> 2) & 0x1,
          (err_code >> 3) & 0x1,
          (err_code >> 4) & 0x1);
    }
}

void elkvm_pager_dump_page_tables(struct kvm_pager *pager) {
	printf(" Page Tables:\n");
	printf(" ------------\n");

	elkvm_pager_dump_table(pager, pager->host_pml4_p, 4);
	printf(" ------------\n");
	return;
}

void elkvm_pager_dump_table(struct kvm_pager *pager, void *host_p, int level) {
	if(level < 1) {
		return;
	}

	char *tname;
	switch(level) {
		case 1: tname = "Page Table\0";
						break;
		case 2: tname = "Page Directory\0";
						break;
		case 3: tname = "Page Directory Pointer Table\0";
						break;
		case 4: tname = "PML4\0";
						break;
		default: tname = "Invalid Level\0";
						 break;
	}

	uint64_t *entry = host_p;
	void *present[512];
	int entries = 0;

	uint64_t guest_physical = host_to_guest_physical(pager, host_p);
	printf(" %s with host base %p (0x%lx)\n", tname, host_p, guest_physical);
	printf(" Offset P W Us WTC C A 6-8 9-11\tNext\t\tNXE\n");

	for(int i = 0; i < 512; i++) {
		if(*entry & 0x1) {
			uint64_t entry_guest_physical = *entry & 0xFFFFFFFFFF000;
			printf(" %3i    %1lx %1lx  %1lx   %1lx %1lx %1lx   %1lx    %1lx\t%011lx\t%1lx\n",
					i,
					*entry & 0x1,
					(*entry & 0x2) >> 1,
					(*entry & 0x4) >> 2,
					(*entry & 0x8) >> 3,
					(*entry & 0x10) >> 4,
					(*entry & 0x20) >> 5,
					(*entry >> 6) & 0x7,
					(*entry >> 9) & 0x7,
					entry_guest_physical,
					(*entry >> 63));
			present[entries++] = (void *)entry_guest_physical +
				pager->system_chunk.userspace_addr;
      if(*entry & 0x1) {
        assert(entry_guest_physical != 0);
      }
		}
		entry++;
	}
	printf(" --------\n");
	printf("\n");

	if(level > 1) {
		for(int i = 0; i<entries; i++) {
			elkvm_pager_dump_table(pager, present[i], level-1);
		}
	}
	return;
}

void elkvm_pager_slot_dump(struct kvm_pager *pager) {
  printf("FREE SLOT COUNT: %i\n", pager->free_slot_id);
  printf("SLOTS: ");
  for(int i = 0; i <= pager->free_slot_id; i++) {
    printf("%u ", pager->free_slot[i]);
  }
  printf("\n");
}

/*
 * \brief Translate a host address into a guest physical address
*/
uint64_t host_to_guest_physical(struct kvm_pager *pager, void *host_p) {
	struct kvm_userspace_memory_region *region =
		elkvm_pager_find_region_for_host_p(pager, host_p);
	if(region == NULL) {
		return 0;
	}
	assert(region->userspace_addr <= (uint64_t)host_p);
	return (uint64_t)(host_p - region->userspace_addr + region->guest_phys_addr);
}

bool address_in_region(struct kvm_userspace_memory_region *r,
    void *host_addr) {
  return ((void *)r->userspace_addr <= host_addr) &&
      (host_addr < ((void *)r->userspace_addr + r->memory_size));
}

bool guest_address_in_region(struct kvm_userspace_memory_region *r,
    uint64_t guest_physical) {
  return (r->guest_phys_addr <= guest_physical) &&
      (guest_physical < (r->guest_phys_addr + r->memory_size));
}

/*
 * \brief Check if an entry exists in a pml4, pdpt, pd or pt
*/
bool entry_exists(uint64_t *e) {
	return *e & 0x1;
}

guestptr_t page_begin(guestptr_t addr) {
  return (addr & ~(ELKVM_PAGESIZE-1));
}

bool page_aligned(guestptr_t addr) {
  return ((addr & ~(ELKVM_PAGESIZE-1)) == addr);
}

guestptr_t next_page(guestptr_t addr) {
  return (addr & ~(ELKVM_PAGESIZE-1)) + ELKVM_PAGESIZE;
}

int pages_from_size(uint64_t size) {
  if(size % ELKVM_PAGESIZE) {
    return (size / ELKVM_PAGESIZE) + 1;
  } else {
    return size / ELKVM_PAGESIZE;
  }
}

int page_remain(guestptr_t addr) {
  return ELKVM_PAGESIZE - (addr & (ELKVM_PAGESIZE-1));
}

unsigned int offset_in_page(guestptr_t addr) {
  return addr & (ELKVM_PAGESIZE-1);
}

uint64_t pagesize_align(uint64_t size) {
  return ((size & ~(ELKVM_PAGESIZE-1)) + ELKVM_PAGESIZE);
}

