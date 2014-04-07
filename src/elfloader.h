#pragma once

#include <gelf.h>
#include <libelf.h>

#include "elkvm.h"

#define LD_LINUX_SO_BASE 0x7FFFF0000000

#ifdef __cplusplus
extern "C" {
#endif

struct Elf_binary {
	int fd;
	Elf *e;
	size_t phdr_num;
  bool static_linkage;
  bool shared_obj;
  int elfclass;
  char *loader;
  uint64_t entry;
};

/*
 * Loads an ELF binary into the VM's system_chunk
*/
int elkvm_load_binary(struct kvm_vm *vm, const char *binary);

/*
 * Load the Program headers of an ELF binary
*/
int elkvm_loader_parse_program(struct kvm_vm *, struct Elf_binary *);

/*
 * Load a single program header from the ELF binary into the specified buffer
*/
int elkvm_loader_load_program_header(struct Elf_binary *, GElf_Phdr,
		struct elkvm_memory_region *);

/*
 * Check for correct ELF headers
*/
int elkvm_loader_check_elf(struct kvm_vm *, struct Elf_binary *);

int elkvm_loader_pt_load(struct kvm_vm *vm, GElf_Phdr phdr, struct Elf_binary *bin);
GElf_Phdr elkvm_loader_find_data_header(struct Elf_binary *bin);
GElf_Phdr elkvm_loader_find_text_header(struct Elf_binary *bin);

int elkvm_loader_pad_begin(struct elkvm_memory_region *region,
    struct Elf_binary *bin, GElf_Phdr phdr);

int elkvm_loader_read_segment(struct elkvm_memory_region *region,
    struct Elf_binary *bin, GElf_Phdr phdr);

int elkvm_loader_pad_end(struct elkvm_memory_region *region,
    struct Elf_binary *bin, GElf_Phdr phdr);

int elkvm_loader_pad_text_end(struct Elf_binary *bin, void *host_p, size_t padsize);

int elkvm_loader_pad_text_begin(struct elkvm_memory_region *region,
    struct Elf_binary *bin, size_t padsize);

int elkvm_loader_pad_data_begin(struct elkvm_memory_region *region,
    struct Elf_binary *bin, size_t padsize);

int elkvm_heap_initialize(struct elkvm_memory_region *, uint64_t);

#ifdef __cplusplus
}
#endif
