#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <elfloader.h>
#include <elkvm.h>
#include <pager.h>


int elfloader_load_binary(struct kvm_vm *vm, const char *binary) {
	if(binary == "") {
		return -EIO;
	}

	if(vm->pager.system_chunk.userspace_addr == NULL) {
		return -EIO;
	}

	struct Elf_binary bin;

	bin.fd = open(binary, O_RDONLY);
	if(bin.fd < 1) {
		return -errno;
	}

	if(elf_version(EV_CURRENT) == EV_NONE) {
		return -1;
	}
	
	bin.e = elf_begin(bin.fd, ELF_C_READ, NULL);
	if(bin.e == NULL) {
		return -1;
	}

	int err = elfloader_check_elf(bin.e);
	if(err) {
		return err;
	}	


	err = elfloader_load_program_headers(vm, &bin);
	if(err) {
		return err;
	}

//	err = elfloader_load_section_headers(vm, &bin);
//	if(err) {
//		return err;
//	}

	elf_end(bin.e);
	close(bin.fd);

	return 0;
}

int elfloader_check_elf(Elf *e) {
	GElf_Ehdr ehdr;

	int ek = elf_kind(e);
	
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

int elfloader_load_program_headers(struct kvm_vm *vm, struct Elf_binary *bin) {

	int err = elf_getphdrnum(bin->e, &bin->phdr_num);
	if(err) {
		return -err;
	}

	char *buf = (char *)vm->pager.system_chunk.userspace_addr;

	bool pt_interp_forbidden = false;
	bool pt_phdr_forbidden = false;

	for(int i = 0; i < bin->phdr_num; i++) {
		GElf_Phdr phdr;
		gelf_getphdr(bin->e, i, &phdr);

		/* a program header's memsize may be large than or equal to its filesize */
		if(phdr.p_filesz > phdr.p_memsz) {
			return -1;
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
				err = elfloader_load_program_header(vm, bin, phdr, buf);
				if(err) {
					return err;
				}
				int pages = (phdr.p_memsz / 0x1000) + 1;
				for(int page = 0; page < pages; page++) {
					void *host_physical_p = buf + (page * 0x1000);
					err = kvm_pager_create_mapping(&vm->pager, host_physical_p, phdr.p_vaddr & ~0xFFF);
					if(err) {
						return err;
					}
				}
		
				/*
				 * advance the buffer page-wise for now
				 */
				buf = buf + (pages * 0x1000);

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

int elfloader_load_program_header(struct kvm_vm *vm, struct Elf_binary *bin,
		GElf_Phdr phdr, char *buf) {

		/*
		 * ELF specification says to read the whole page into memory
		 * this means we have "dirty" bytes at the beginning and end
		 * of every loadable program header
		 */

		/*
		 * buffers need to be page aligned
		*/
		if(((uint64_t)buf & ~0xFFF) != buf) {
			return -EIO;
		}
		
		/*
		 * make sure we are going to read full pages
		 */
		int remaining_bytes = ((phdr.p_filesz + (phdr.p_offset & 0xFFF)) & ~0xFFF)
			+ 0x1000;
		int bufsize = remaining_bytes < 32768 ? remaining_bytes : 32768;

		int bytes = 0;
		/*
		 * seek to the beginning of the first page that contains the program
		 * header we are to load
		 */
		int off = lseek(bin->fd, phdr.p_offset & ~0xFFF, SEEK_SET);
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

		/*
		 * if the header's memsize is larger than its filesize we are supposed to
		 * fill the rest with 0s
		*/
		int bytes_diff = phdr.p_memsz - phdr.p_filesz;
		if(bytes_diff > 0) {
			memset(buf, 0, bytes_diff);
		}

		return 0;
}

int elfloader_load_section_headers(struct kvm_vm *vm, struct Elf_binary *bin) {
	return -1;
}

