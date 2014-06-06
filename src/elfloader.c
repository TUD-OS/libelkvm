#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "elfloader.h"
#include <elkvm.h>
#include <kvm.h>
#include <pager.h>
#include <region-c.h>
#include <vcpu.h>


int elkvm_load_binary(struct kvm_vm *vm, const char *binary) {
  if(strcmp(binary, "") == 0) {
		return -EIO;
	}

	if(vm->pager.system_chunk.userspace_addr == 0) {
		return -EIO;
	}

	struct Elf_binary bin;

	bin.fd = open(binary, O_RDONLY);
	if(bin.fd < 1) {
		return -errno;
	}

	if(elf_version(EV_CURRENT) == EV_NONE) {
		return -EIO;
	}

	bin.e = elf_begin(bin.fd, ELF_C_READ, NULL);
	if(bin.e == NULL) {
		return -ENOMEM;
	}

	GElf_Ehdr ehdr;

	if(gelf_getehdr(bin.e, &ehdr) == NULL) {
		return -EIO;
	}

	int err = elkvm_loader_check_elf(bin.e);
	if(err) {
		return err;
	}

	err = elkvm_loader_parse_program(vm, &bin);
	if(err) {
		return err;
	}

	err = kvm_vcpu_set_rip(vm->vcpus->vcpu, ehdr.e_entry);
	if(err) {
		return err;
	}

	elf_end(bin.e);
	close(bin.fd);

	return 0;
}

int elkvm_loader_check_elf(Elf *e) {
	GElf_Ehdr ehdr;
	if(gelf_getehdr(e, &ehdr) == NULL) {
		return -1;
	}

	if(gelf_getehdr(e, &ehdr) == NULL) {
		return -1;
	}

	/* for now process only 64bit ELF files */
	int elfclass = gelf_getclass(e);
	switch(elfclass) {
		case ELFCLASSNONE:
		case ELFCLASS32:
			return -1;
	}

	return 0;
}

int elkvm_loader_parse_program(struct kvm_vm *vm, struct Elf_binary *bin) {

	int err = elf_getphdrnum(bin->e, &bin->phdr_num);
	if(err) {
		return -err;
	}

	bool pt_interp_forbidden = false;
	bool pt_phdr_forbidden = false;

	for(unsigned i = 0; i < bin->phdr_num; i++) {
		GElf_Phdr phdr;
		gelf_getphdr(bin->e, i, &phdr);

		/* a program header's memsize may be large than or equal to its filesize */
		if(phdr.p_filesz > phdr.p_memsz) {
			return -EIO;
		}

		switch(phdr.p_type) {
			/* ignore these headers for now */
			case PT_NULL:
			case PT_DYNAMIC:
			case PT_NOTE:
			case PT_SHLIB:
			case PT_LOPROC:
			case PT_HIPROC:
				continue;
			case PT_INTERP:
				if(pt_interp_forbidden) {
					return -1;
				}
				pt_interp_forbidden = true;
				continue;
			case PT_LOAD:
				pt_interp_forbidden = true;
				pt_phdr_forbidden = true;
        elkvm_loader_pt_load(vm, phdr, bin);
				break;
			case PT_PHDR:
				if(pt_phdr_forbidden) {
					return -1;
				}
				pt_phdr_forbidden = true;
				break;
		}

	}

	return 0;
}

int elkvm_loader_pt_load(struct kvm_vm *vm, GElf_Phdr phdr, struct Elf_binary *bin) {
	uint64_t total_size = phdr.p_memsz + offset_in_page(phdr.p_vaddr);
	struct elkvm_memory_region *loadable_region =
		elkvm_region_create(total_size);
  loadable_region->guest_virtual = page_begin(phdr.p_vaddr);

	int err = elkvm_loader_load_program_header(bin, phdr, loadable_region);
	if(err) {
		return err;
	}

  ptopt_t opts = 0;
  if(phdr.p_flags & PF_X) {
    opts |= PT_OPT_EXEC;
  }
  if(phdr.p_flags & PF_W) {
    opts |= PT_OPT_WRITE;
  }

  int pages = pages_from_size(total_size);
  err = elkvm_pager_map_region(&vm->pager, loadable_region->host_base_p,
      loadable_region->guest_virtual, pages, opts);

	if(phdr.p_flags & PF_X) {
		/* executable region should be text */
		vm->text = loadable_region;
	} else if(phdr.p_flags & PF_W) {
    err = elkvm_heap_initialize(loadable_region, total_size);
    if(err) {
      return err;
    }
	}

  return 0;
}

int elkvm_loader_load_program_header(struct Elf_binary *bin,
		GElf_Phdr phdr, struct elkvm_memory_region *region) {

		/*
		 * ELF specification says to read the whole page into memory
		 * this means we have "dirty" bytes at the beginning and end
		 * of every loadable program header
     * These bytes are to be filled, with different data depending on
     * if we are dealing with the text or the data region here.
     * For Text the padding in the beginning should be filled with
     * the ELF header, the program header table and "other information"
     * Padding in the end should be a copy of the beginning of data
     * For Data the padding in the beginning should be filled with
     * a copy of the end of text
     * Padding in the end may contain file information
		 */

  if(!page_aligned((uint64_t)region->host_base_p)) {
    return -EIO;
  }

  elkvm_loader_pad_begin(region, bin, phdr);
  elkvm_loader_read_segment(region, bin, phdr);
  elkvm_loader_pad_end(region, bin, phdr);

  return 0;
}

int elkvm_loader_pad_end(struct elkvm_memory_region *region,
    struct Elf_binary *bin, GElf_Phdr phdr) {
  void *host_p = region->host_base_p + offset_in_page(phdr.p_vaddr) + phdr.p_filesz;
  size_t padsize = page_remain((uint64_t)host_p);

  if(phdr.p_flags & PF_X) {
    /* executable segment should be text */
    return elkvm_loader_pad_text_end(bin, host_p, padsize);
  }
  if(phdr.p_flags & PF_W) {
    padsize += (phdr.p_memsz - phdr.p_filesz);
    /* set uninitialized data to 0s */
    memset(host_p, 0, padsize);
    //elkvm_loader_pad_data_end();
    return 0;
    /* TODO set brk */
  }

  /* this should never happen */
  assert(false);
  return -1;

}

int elkvm_loader_read_segment(struct elkvm_memory_region *region,
    struct Elf_binary *bin, GElf_Phdr phdr) {
  char *buf = region->host_base_p + offset_in_page(phdr.p_vaddr);

	/*
	 * make sure we are going to read full pages
	 */
	int remaining_bytes = phdr.p_filesz;
	int bufsize = remaining_bytes < 32768 ? remaining_bytes : 32768;

	int bytes = 0;

	int off = lseek(bin->fd, phdr.p_offset, SEEK_SET);
	if(off < 0) {
		return -errno;
	}

	while((bytes = read(bin->fd, buf, bufsize)) > 0) {
		remaining_bytes -= bytes;
		if(remaining_bytes < bufsize) {
			bufsize = remaining_bytes;
		}
		buf += bytes;
	}

  return 0;

}

int elkvm_loader_pad_begin(struct elkvm_memory_region *region,
    struct Elf_binary *bin, GElf_Phdr phdr) {

  size_t padsize = offset_in_page(phdr.p_vaddr);

  if(phdr.p_flags & PF_X) {
    /* executable segment should be text */
    return elkvm_loader_pad_text_begin(region, bin, padsize);
  }
  if(phdr.p_flags & PF_W) {
    return elkvm_loader_pad_data_begin(region, bin, padsize);
  }

  /* this should never happen */
  assert(false);
  return -1;
}

int elkvm_loader_pad_text_end(struct Elf_binary *bin, void *host_p, size_t padsize) {
  /*
   * find the first page of the data segment and pad the remainder of the
   * last page of text with its contents
   */

  GElf_Phdr data_header = elkvm_loader_find_data_header(bin);

	int off = lseek(bin->fd, data_header.p_offset, SEEK_SET);
	if(off < 0) {
		return -errno;
	}

	size_t bytes = read(bin->fd, host_p, padsize);
  assert(bytes == padsize);

  return 0;
}

int elkvm_loader_pad_text_begin(struct elkvm_memory_region *region,
    struct Elf_binary *bin, size_t padsize) {
  assert(bin->e > (Elf *)NULL);

  GElf_Ehdr ehdr;
  gelf_getehdr(bin->e, &ehdr);

  memcpy(region->host_base_p, &ehdr, padsize);

  return 0;
}

int elkvm_loader_pad_data_begin(struct elkvm_memory_region *region,
    struct Elf_binary *bin, size_t padsize) {
  GElf_Phdr text_header = elkvm_loader_find_text_header(bin);

  uint64_t text_end = text_header.p_offset + text_header.p_filesz;

	int off = lseek(bin->fd, text_end - padsize - 1, SEEK_SET);
	if(off < 0) {
		return -errno;
	}

	size_t bytes = read(bin->fd, region->host_base_p, padsize);
  assert(bytes == padsize);

  return 0;
}

GElf_Phdr elkvm_loader_find_data_header(struct Elf_binary *bin) {
  GElf_Phdr phdr;
	for(unsigned i = 0; i < bin->phdr_num; i++) {
		gelf_getphdr(bin->e, i, &phdr);

    if(phdr.p_type == PT_LOAD &&
        phdr.p_flags & PF_W) {
      return phdr;
    }
  }

  /* every elf file should have a data header */
  assert(false);
  return phdr;
}

GElf_Phdr elkvm_loader_find_text_header(struct Elf_binary *bin) {
  GElf_Phdr phdr;
	for(unsigned i = 0; i < bin->phdr_num; i++) {
		gelf_getphdr(bin->e, i, &phdr);

    if(phdr.p_type == PT_LOAD &&
        phdr.p_flags & PF_X) {
      return phdr;
    }
  }

  /* every elf file should have a text header */
  assert(false);
  return phdr;
}

