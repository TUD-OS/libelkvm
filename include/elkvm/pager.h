#pragma once

#include <memory>
#include <vector>

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ELKVM_PAGER_MEMSIZE 16*1024*1024
#define ELKVM_SYSTEM_MEMSIZE 16*1024*1024
#define ELKVM_SYSTEM_MEMGROW 128*1024*1024
#define KERNEL_SPACE_BOTTOM 0xFFFF800000000000
#define ADDRESS_SPACE_TOP 0xFFFFFFFFFFFFFFFF

#define PT_BIT_PRESENT     0x1
#define PT_BIT_WRITEABLE   0x2
#define PT_BIT_USER        0x4
#define PT_BIT_WRITE_CACHE 0x8
#define PT_BIT_NO_CACHE    0x16
#define PT_BIT_USED        0x32
#define PT_BIT_LARGEPAGE   (1L << 7)
#define PT_BIT_NXE         (1L << 63)

#define HOST_PAGESIZE        0x1000
#define ELKVM_PAGESIZE       0x1000
#define ELKVM_PAGESIZE_LARGE 0x200000
#define ELKVM_PAGESIZE_HUGE  0x100000000
/*
 * KVM allows only for 32 memory slots in Linux 3.8
 * and 128 slots on Linux 3.11
 * its down to 125 slots in Linux 3.13
 */
#define KVM_MEMORY_SLOTS 125

typedef unsigned int ptopt_t;
#define PT_OPT_WRITE 0x1
#define PT_OPT_EXEC  0x2
#define PT_OPT_LARGE 0x4
#define PT_OPT_HUGE  0x8

typedef uint64_t ptentry_t;

struct kvm_userspace_memory_region *
elkvm_pager_alloc_chunk(struct kvm_pager *const pager, void *addr,
    uint64_t chunk_size, int flags);
/*
	Let Pager create a mem chunk of the given size. The mem_chunk will be added
  to the end of the other_chunks list
*/
int elkvm_pager_create_mem_chunk(struct kvm_pager *const, void **, int);

/*
 * Maps a new mem chunk into the VM
*/
int elkvm_pager_map_chunk(struct kvm_vm *, struct kvm_userspace_memory_region *);

int elkvm_pager_free_chunk(struct kvm_pager *pager,
    struct kvm_userspace_memory_region *chunk);

struct kvm_userspace_memory_region elkvm_pager_get_system_chunk(
    struct kvm_pager *);
struct kvm_userspace_memory_region *elkvm_pager_get_chunk(struct kvm_pager *, int);


int elkvm_pager_unmap_region(struct kvm_pager *pager, uint64_t guest_start_addr,
    unsigned pages);

/*
 * \brief Destroy a Mapping in the Page tables
 */
int elkvm_pager_destroy_mapping(struct kvm_pager *pager, uint64_t guest_virtual);


/*
 * \brief find an entry in a pml4, pdpt, pd or pt
 * Args: pager, host table base pointer, guest virtual address, offsets
*/
uint64_t *elkvm_pager_find_table_entry(uint64_t *, guestptr_t,
		int, int);

/*
 * \brief Creates a new table and puts the entry in a pml4, pdpt, pd or pt
 * Args: pager, entry, writeable, executable
*/
int elkvm_pager_create_table(struct kvm_pager *, uint64_t *, ptopt_t opts);

int elkvm_pager_handle_pagefault(struct kvm_pager *, uint64_t, uint32_t);

void elkvm_pager_dump_page_fault_info(guestptr_t pfla,
    uint32_t err_code, void *host_p);
void elkvm_pager_dump_page_tables(struct kvm_pager *);
void elkvm_pager_dump_table(struct kvm_pager *, void *, int);

bool address_in_region(struct kvm_userspace_memory_region *r, void *host_addr);
bool guest_address_in_region(struct kvm_userspace_memory_region *r,
    uint64_t guest_physical);
guestptr_t page_begin(guestptr_t addr);
bool page_aligned(guestptr_t addr);
guestptr_t next_page(guestptr_t addr);
int pages_from_size(uint64_t size);
int page_remain(guestptr_t addr);
unsigned int offset_in_page(guestptr_t addr);
uint64_t pagesize_align(uint64_t size);

#ifdef __cplusplus
}
#endif

namespace Elkvm {

  class Region;

  class PagerX86_64 {
    private:
      const int _vmfd;
      std::vector<std::shared_ptr<struct kvm_userspace_memory_region>> chunks;
      void *host_pml4_p;
      void *host_next_free_tbl_p;
      guestptr_t guest_next_free;
      size_t total_memsz;
      std::vector<uint32_t> free_slots;

      std::shared_ptr<struct kvm_userspace_memory_region> alloc_chunk(void *addr,
          size_t chunk_size, int flags);

      void create_entry(ptentry_t *host_entry_p, guestptr_t guest_next,
          ptopt_t opts) const;

      int create_page_tables();
      int create_table(ptentry_t *host_entry_p, ptopt_t opts);

      ptentry_t *find_next_table(ptentry_t *tbl_entry_p) const;

      ptentry_t *find_table_entry(ptentry_t *tbl_base_p,
          guestptr_t addr, off64_t off_low, off64_t off_high) const;

      ptentry_t *page_table_walk(guestptr_t guest_virtual, ptopt_t opts,
          bool create);

    public:
      PagerX86_64(int vmfd);
      int set_pml4(std::shared_ptr<Region> r);

      std::vector<std::shared_ptr<struct kvm_userspace_memory_region *>>::size_type
        chunk_count() const { return chunks.size(); }

      int create_mem_chunk(void **host_p, int chunk_size);
      void dump_page_tables() const;
      void dump_table(ptentry_t *host_p, int level) const;

      std::shared_ptr<struct kvm_userspace_memory_region>
        find_chunk_for_host_p(void *host_mem_p) const;

      int free_page(guestptr_t guest_virtual);

      std::shared_ptr<struct kvm_userspace_memory_region> get_chunk(
          std::vector<std::shared_ptr<struct kvm_userspace_memory_region *>>::size_type chunk)
        const;

      /* XXX make this const */
      void *get_host_p(guestptr_t guest_virtual);
      int handle_pagefault(guestptr_t pfla, uint32_t err_code, bool debug);
      guestptr_t host_to_guest_physical(void *host_p) const;

      int map_chunk_to_kvm(
          std::shared_ptr<struct kvm_userspace_memory_region> chunk);

      guestptr_t map_kernel_page(void *host_mem_p, ptopt_t opts);
      int map_region(void *start_p, guestptr_t start_addr,
          unsigned pages, ptopt_t opts);
      int map_user_page(void *host_mem_p, guestptr_t guest_virtual,
          ptopt_t opts);

      int unmap_region(guestptr_t start_addr, unsigned pages);
      int update_entry(ptentry_t *entry, ptopt_t opts);
  };

  bool contains_address(std::shared_ptr<struct kvm_userspace_memory_region> chunk,
      void *addr);
  bool contains_address(std::shared_ptr<struct kvm_userspace_memory_region> chunk,
      guestptr_t addr);
  bool contains_phys_address(
      std::shared_ptr<struct kvm_userspace_memory_region> chunk, guestptr_t addr);

  void dump_page_fault_info(guestptr_t pfla, uint32_t err_code, void *host_p);
  bool entry_exists(ptentry_t *entry);

  //namespace Elkvm
}
