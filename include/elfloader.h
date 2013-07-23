#pragma once

#include <gelf.h>
#include <libelf.h>

#include <elkvm.h>

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
int elfloader_load_program_header(struct kvm_vm *, struct Elf_binary *, GElf_Phdr, char *);

/*
 * Load the Section headers of an ELF binary
*/
int elfloader_load_section_headers(struct kvm_vm *, struct Elf_binary *);

/*
 * Check for correct ELF headers
*/
int elfloader_check_elf(Elf *);

