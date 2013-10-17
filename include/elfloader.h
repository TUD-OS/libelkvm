#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <gelf.h>
#include <libelf.h>

#include "elkvm.h"

struct Elf_binary {
	int fd;
	Elf *e;
	size_t phdr_num;
};

/*
 * Loads an ELF binary into the beginnig of the VM's system_chunk
*/
int elfloader_load_binary(struct kvm_vm *, const char *);

/*
 * Load the Program headers of an ELF binary
*/
int elfloader_load_program_headers(struct kvm_vm *, struct Elf_binary *);

/*
 * Load a single program header from the ELF binary into the specified buffer
*/
int elfloader_load_program_header(struct kvm_vm *, struct Elf_binary *, GElf_Phdr,
		struct elkvm_memory_region *);

/*
 * Load the Section headers of an ELF binary
*/
int elfloader_load_section_headers(struct kvm_vm *, struct Elf_binary *);

/*
 * Check for correct ELF headers
*/
int elfloader_check_elf(Elf *);

int elkvm_loader_pt_load(struct kvm_vm *vm, GElf_Phdr phdr, struct Elf_binary *bin);
GElf_Phdr elkvm_loader_find_data_header(struct Elf_binary *bin);
GElf_Phdr elkvm_loader_find_text_header(struct Elf_binary *bin);

int elkvm_loader_pad_begin(struct kvm_vm *vm, struct elkvm_memory_region *region,
    struct Elf_binary *bin, GElf_Phdr phdr);

int elkvm_loader_read_segment(struct kvm_vm *vm,
    struct elkvm_memory_region *region, struct Elf_binary *bin, GElf_Phdr phdr);

int elkvm_loader_pad_end(struct kvm_vm *vm, struct elkvm_memory_region *region,
    struct Elf_binary *bin, GElf_Phdr phdr);

int elkvm_loader_pad_text_end(struct kvm_vm *vm,
    struct elkvm_memory_region *region, struct Elf_binary *bin,
    void *host_p, size_t padsize);

int elkvm_loader_pad_text_begin(struct kvm_vm *vm,
    struct elkvm_memory_region *region, struct Elf_binary *bin,
    size_t padsize);

int elkvm_loader_pad_data_begin(struct kvm_vm *vm,
    struct elkvm_memory_region *region, struct Elf_binary *bin,
    size_t padsize);

#ifdef __cplusplus
}
#endif
