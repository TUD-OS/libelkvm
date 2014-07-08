#include <algorithm>
#include <iostream>
#include <string>

#include <errno.h>
#include <stdlib.h>
#include <sys/ioctl.h>

#include <elkvm.h>
#include <pager.h>
#include <stack-c.h>
#include <vcpu.h>
#include <region.h>

namespace Elkvm {
  extern std::unique_ptr<RegionManager> rm;

  PagerX86_64::PagerX86_64(int vmfd) :
  _vmfd(vmfd) {
    if(vmfd < 1) {
      throw;
    }
  }

  int PagerX86_64::set_pml4(std::shared_ptr<Region> r) {
    host_pml4_p = r->base_address();
    guestptr_t pml4_guest_physical = host_to_guest_physical(host_pml4_p);
    guest_next_free = KERNEL_SPACE_BOTTOM;

    int err = create_page_tables();
    assert(err == 0 && "could not create page tables");

    return pml4_guest_physical;
  }

  std::shared_ptr<struct kvm_userspace_memory_region>
  PagerX86_64::alloc_chunk(void *addr, size_t chunk_size, int flags) {
    std::shared_ptr<struct kvm_userspace_memory_region>chunk =
      std::make_shared<struct kvm_userspace_memory_region>();
    if(!chunk) {
      return nullptr;
    }

    chunk->userspace_addr = (__u64)addr;
    chunk->guest_phys_addr = total_memsz;
    chunk->memory_size = chunk_size;
    chunk->flags = flags;
    total_memsz += chunk_size;

    chunk->slot = chunks.size();
    chunks.push_back(chunk);

    if(!free_slots.empty()) {
      chunk->slot = free_slots.back();
      free_slots.pop_back();
    }

    return chunk;
  }

  void PagerX86_64::create_entry(ptentry_t *host_entry_p, guestptr_t guest_next,
      ptopt_t opts) const {
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
  }

  int PagerX86_64::create_mem_chunk(void **host_p, int chunk_size) {
    /* keep sizes page aligned */
    if((chunk_size & ~(HOST_PAGESIZE - 1)) != chunk_size) {
      return -EIO;
    }

    int err = posix_memalign(host_p, HOST_PAGESIZE, chunk_size);
    if(err) {
      return err;
    }
    auto chunk = alloc_chunk(*host_p, chunk_size, 0);
    if(chunk == nullptr) {
      free(*host_p);
      *host_p = NULL;
      return -ENOMEM;
    }

    err = map_chunk_to_kvm(chunk);
    return err;
  }

  int PagerX86_64::create_page_tables() {
    assert(host_pml4_p != nullptr);
    assert(chunks[0]->memory_size >= ELKVM_SYSTEM_MEMSIZE);

    memset(host_pml4_p, 0, ELKVM_SYSTEM_MEMSIZE);
    host_next_free_tbl_p = reinterpret_cast<char *>(host_pml4_p) + HOST_PAGESIZE;

    return 0;
  }

  int PagerX86_64::create_table(ptentry_t *host_entry_p, ptopt_t opts) {
    guestptr_t guest_next_tbl = host_to_guest_physical(host_next_free_tbl_p);
    assert(guest_next_tbl != 0x0);

    memset(host_next_free_tbl_p, 0, HOST_PAGESIZE);
    host_next_free_tbl_p =
      reinterpret_cast<char *>(host_next_free_tbl_p) + HOST_PAGESIZE;

    create_entry(host_entry_p, guest_next_tbl, opts);
    return 0;
  }

  void PagerX86_64::dump_page_tables() const {
    printf(" Page Tables:\n");
    printf(" ------------\n");

    dump_table(reinterpret_cast<ptentry_t *>(host_pml4_p), 4);
    printf(" ------------\n");
    return;
  }

  void PagerX86_64::dump_table(ptentry_t *host_p, int level) const {
    assert(!chunks.empty());

    if(level < 1) {
      return;
    }

    std::string tname;
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

    ptentry_t *entry = host_p;
    ptentry_t *present[512];
    int entries = 0;

    guestptr_t guest_physical = host_to_guest_physical(host_p);
    std::cout << tname << " with host base " << host_p << " (0x" << std::hex
      << guest_physical << ")\n";
    printf(" Offset P W Us WTC C A 6-8 9-11\tNext\t\tNXE\n");

    for(int i = 0; i < 512; i++) {
      if(*entry & 0x1) {
        ptentry_t entry_guest_physical = *entry & 0xFFFFFFFFFF000;
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
        present[entries++] = reinterpret_cast<ptentry_t *>(
          reinterpret_cast<char *>(entry_guest_physical) +
          chunks[0]->userspace_addr);
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
        dump_table(present[i], level-1);
      }
    }
    return;
  }

  ptentry_t *PagerX86_64::find_next_table(ptentry_t *tbl_entry_p) const {
    if(!entry_exists(tbl_entry_p)) {
      return NULL;
    }

    /* location of the next table is in bits 12 - 51 of the entry */
    ptentry_t guest_next_tbl = *tbl_entry_p & 0x000FFFFFFFFFF000;
    return (ptentry_t *)(chunks[0]->userspace_addr + guest_next_tbl);
  }

  ptentry_t *PagerX86_64::find_table_entry(ptentry_t *tbl_base_p,
      guestptr_t addr, off64_t off_low, off64_t off_high) const {
    off64_t off = (addr << (63 - off_high)) >> ((63 - off_high) + off_low);

    ptentry_t *entry = tbl_base_p + off;
    return entry;
  }

  int PagerX86_64::free_page(guestptr_t guest_virtual) {
    ptentry_t *pt_entry = page_table_walk(guest_virtual, 0, 0);

    if(pt_entry == NULL) {
      return -1;
    }

    *pt_entry = 0;
    return 0;
  }

  /* XXX make this const */
  void *PagerX86_64::get_host_p(guestptr_t guest_virtual) {
    if(guest_virtual == 0x0) {
      return nullptr;
    }

    ptentry_t *entry = page_table_walk(guest_virtual, 0, 0);
    if(entry == NULL) {
      return NULL;
    }

    std::shared_ptr<struct kvm_userspace_memory_region> chunk = nullptr;
    guestptr_t guest_physical =
      (*entry & 0x000FFFFFFFFFF000) | (guest_virtual & (ELKVM_PAGESIZE-1));

    for(const auto &c : chunks) {
      if(contains_phys_address(c, guest_physical)) {
        chunk = c;
        break;
      }
    }
    if(chunk == nullptr) {
      return NULL;
    }

    return (void *)((guest_physical - chunk->guest_phys_addr)
        + chunk->userspace_addr);
  }

  int PagerX86_64::handle_pagefault(guestptr_t pfla, uint32_t err_code,
      bool debug) {
    void *host_p = get_host_p(pfla);

//    if(pager->vm->debug) {
//      printf("PFLA: 0x%lx\nCURRENT STACK TOP:0x%lx\n",
//          pfla, pager->vm->current_user_stack->guest_virtual);
//    }
    if(elkvm_check_stack_grow(pfla)) {
      if(debug) {
        dump_page_fault_info(pfla, err_code, host_p);
      }
      return 0;
    }

    dump_page_fault_info(pfla, err_code, host_p);
    if(host_p != NULL) {
      dump_page_tables();
    }

    return 1;
}



  guestptr_t PagerX86_64::host_to_guest_physical(void *host_p) const {
    auto chunk = find_chunk_for_host_p(host_p);
    if(chunk == NULL) {
      return 0;
    }

    return (guestptr_t)(reinterpret_cast<char *>(host_p) - chunk->userspace_addr
        + chunk->guest_phys_addr);
  }

  int PagerX86_64::map_chunk_to_kvm(
      std::shared_ptr<struct kvm_userspace_memory_region> chunk) {
      if(chunk->memory_size == 0) {
        free_slots.push_back(chunk->slot);
        auto it = std::find(chunks.begin(), chunks.end(), chunk);
        if(it != chunks.end()) {
          chunks.erase(it);
        }
      }

      assert(chunk->slot < KVM_MEMORY_SLOTS);
      int err = ioctl(_vmfd, KVM_SET_USER_MEMORY_REGION, chunk.get());
      return err ? -errno : 0;
    //  if(err) {
    //    long sz = sysconf(_SC_PAGESIZE);
    //    printf("Could not set memory region\n");
    //    printf("Error No: %i Msg: %s\n", errno, strerror(errno));
    //    printf("Pagesize is: %li\n", sz);
    //    printf("Here are some sanity checks that are applied in kernel:\n");
    //    int ms = chunk->memory_size & (sz-1);
    //    int pa = chunk->guest_phys_addr & (sz-1);
    //    int ua = chunk->userspace_addr & (sz-1);
    //    printf("memory_size & (PAGE_SIZE -1): %i\n", ms);
    //    printf("guest_phys_addr & (PAGE_SIZE-1): %i\n", pa);
    //    printf("userspace_addr & (PAGE_SIZE-1): %i\n", ua);
    //    printf("TODO verify write access\n");
    //    return -errno;
    //  }
    //  return 0;
  }

  std::shared_ptr<struct kvm_userspace_memory_region> PagerX86_64::get_chunk(
      std::vector<std::shared_ptr<struct kvm_userspace_memory_region *>>::size_type chunk)
  const {
    return chunks.at(chunk);
  }

    std::shared_ptr<struct kvm_userspace_memory_region>
    PagerX86_64::find_chunk_for_host_p(void *host_mem_p) const {
      for(const auto &chunk : chunks) {
        if(contains_address(chunk, host_mem_p)) {
          return chunk;
        }
      }

      return NULL;
  }



  guestptr_t PagerX86_64::map_kernel_page(void *host_mem_p, ptopt_t opts) {
    guestptr_t guest_physical = host_to_guest_physical(host_mem_p);
    guestptr_t guest_virtual = (guest_next_free & ~(ELKVM_PAGESIZE-1))
      | (guest_physical & (ELKVM_PAGESIZE-1));
    assert(guest_virtual != 0);

    ptentry_t *pt_entry = page_table_walk(guest_virtual, opts, 1);
    if(pt_entry == NULL) {
      return -EIO;
    }

    while(entry_exists(pt_entry)) {
      pt_entry++;
      guest_virtual = guest_virtual + ELKVM_PAGESIZE;
      if(((ptentry_t)pt_entry & ~(ELKVM_PAGESIZE-1)) == (ptentry_t)pt_entry) {
        /*this page table seems to be completely full, try the next one */
        guest_virtual = guest_virtual + 0x100000;
        assert(guest_virtual != 0);
        pt_entry = page_table_walk(guest_virtual, opts, 1);
      }
    }

    /*
     * TODO setting this page up for user makes interrupts work,
     * fix this!
     */
    create_entry(pt_entry, guest_physical, opts);

    return guest_virtual;
  }

  int PagerX86_64::map_region(void *start_p, guestptr_t start_addr, unsigned pages,
      ptopt_t opts) {
    char *current_p = reinterpret_cast<char *>(start_p);
    guestptr_t current_addr = start_addr;
    for(unsigned i = 0; i < pages; i++) {
      int err = map_user_page(current_p, current_addr, opts);
      if(err) {
        return err;
      }
      current_p    += ELKVM_PAGESIZE;
      current_addr += ELKVM_PAGESIZE;
    }
    return 0;
  }

  int PagerX86_64::map_user_page(void *host_mem_p, guestptr_t guest_virtual,
      ptopt_t opts) {
    assert(guest_virtual != 0x0 && "cannot map NULL to somewhere!");

    assert((host_mem_p < reinterpret_cast<char *>(host_pml4_p)) ||
        host_mem_p >= (reinterpret_cast<char *>(host_pml4_p)
          + ELKVM_SYSTEM_MEMSIZE));

    /* sanity checks on the offset */
    if(((uint64_t)host_mem_p & (ELKVM_PAGESIZE - 1))
        != (guest_virtual & (ELKVM_PAGESIZE - 1))) {
      return -EIO;
    }

    guestptr_t guest_physical = host_to_guest_physical(host_mem_p);
    assert(guest_physical != 0);

    ptentry_t *pt_entry = page_table_walk(guest_virtual, opts, 1);
    assert(pt_entry != NULL && "pt entry must not be NULL after page table walk");

    /* do NOT overwrite existing page table entries! */
    if(entry_exists(pt_entry)) {
      if((*pt_entry & 0x000FFFFFFFFFF000)
          != (guest_physical & ~(ELKVM_PAGESIZE-1))) {
        return -1;
      }
      /* TODO check if flags are the same */
      return 0;
    }

    create_entry(pt_entry, guest_physical, opts);
    return 0;
  }

  ptentry_t *PagerX86_64::page_table_walk(guestptr_t guest_virtual, ptopt_t opts,
      bool create) {
    assert(guest_virtual != 0);

    ptentry_t *table_base = reinterpret_cast<uint64_t *>(host_pml4_p);
    /* we should always have paging in place, when this gets called! */
    assert(table_base != NULL);

    ptentry_t *entry = NULL;
    off64_t addr_low = 39;
    off64_t addr_high = 47;

    /* walk through the three levels of pml4, pdpt, pd, to find the page table */
    for(unsigned i = 0; i < 3; i++) {
      entry = find_table_entry(table_base, guest_virtual, addr_low, addr_high);
      addr_low -= 9;
      addr_high -= 9;
      if(create) {
        int err = update_entry(entry, opts);
        if(err) {
          return NULL;
        }
      } else if(!entry_exists(entry)) {
        return NULL;
      }
      table_base = find_next_table(entry);
    }

    /* now look for the actual page table entry in the pt */
    entry = find_table_entry(table_base, guest_virtual, addr_low, addr_high);
    addr_low -= 9;
    addr_high -= 9;
    if(!create && !entry_exists(entry)) {
      return NULL;
    }

    return entry;
  }

  int PagerX86_64::unmap_region(guestptr_t start_addr, unsigned pages) {

    guestptr_t current_addr = start_addr;
    for(unsigned i = 0; i < pages; i++) {
      int err = free_page(current_addr);
      if(err) {
        return err;
      }
      current_addr += ELKVM_PAGESIZE;
    }

    return 0;
  }

  int PagerX86_64::update_entry(ptentry_t *entry, ptopt_t opts) {
    if(!entry_exists(entry)) {
      int err = create_table(entry, opts);
      if(err) {
        return err;
      }
    }

    if(opts & PT_OPT_WRITE) {
      *entry |= PT_BIT_WRITEABLE;
    }
    if(opts & PT_OPT_EXEC) {
      *entry &= ~PT_BIT_NXE;
    }
    return 0;
  }

  bool contains_address(std::shared_ptr<struct kvm_userspace_memory_region> c,
      void *addr) {
    return ((void *)c->userspace_addr <= reinterpret_cast<char *>(addr)) &&
        (addr < (reinterpret_cast<char *>(c->userspace_addr) + c->memory_size));
  }

  bool contains_phys_address(std::shared_ptr<struct kvm_userspace_memory_region> c,
      guestptr_t addr) {
    return (c->guest_phys_addr <= addr) &&
        (addr < (c->guest_phys_addr + c->memory_size));
  }

  void dump_page_fault_info(guestptr_t pfla, uint32_t err_code, void *host_p) {
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

  bool entry_exists(ptentry_t *e) {
    return *e & 0x1;
  }

  std::ostream &print(std::ostream &os,
      const struct kvm_userspace_memory_region &r) {
    os << "KVM REGION: userspace_addr: 0x" << std::hex << r.userspace_addr
      << " guest physical address: 0x" << r.guest_phys_addr
      << " size: 0x" << r.memory_size
      << " slot: " << std::dec << r.slot
      << std::endl;
    return os;
  }

  //namespace Elkvm
}

void *elkvm_pager_get_host_p(struct kvm_pager *pager __attribute__((unused)),
    guestptr_t addr) {
  return Elkvm::rm->get_pager().get_host_p(addr);
}

guestptr_t elkvm_pager_map_kernel_page(
    struct kvm_pager *pager __attribute__((unused)), void *host_p,
    int write, int exec) {
  ptopt_t opts = 0;
  if(write) {
    opts |= PT_OPT_WRITE;
  }
  if(exec) {
    opts |= PT_OPT_EXEC;
  }
  return Elkvm::rm->get_pager().map_kernel_page(host_p, opts);
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
  if(size % ELKVM_PAGESIZE) {
    return ((size & ~(ELKVM_PAGESIZE-1)) + ELKVM_PAGESIZE);
  } else {
    return size;
  }
}

