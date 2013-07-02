#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <elfloader.h>
#include <elkvm.h>
#include <pager.h>


int elfloader_load_binary(struct kvm_vm *vm, const char *binary) {
	struct Elf_binary bin;

	bin.fd = open(binary, O_RDONLY);
	if(bin.fd < 1) {
		return -errno;
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

	err = elfloader_load_section_headers(vm, &bin);
	if(err) {
		return err;
	}

	elf_end(bin.e);
	close(bin.fd);

	return 0;
}

int elfloader_check_elf(Elf *e) {
	GElf_Ehdr ehdr;

	if(elf_version(EV_CURRENT) == EV_NONE) {
		return -1;
	}

	
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

		switch(pdhr.p_type) {
			/* ignore these headers for now */
			case PT_NULL:
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_NOTE:
			case PT_SHLIB:
			case PT_LOPROC:
			case PT_HIPROC:
				continue;
			case PT_LOAD:
				pt_interp_forbidden = true;
				pt_phdr_forbidden = true;
				break;
			case PT_INTERP:
				pt_interp_forbidden = true;
				break;
			case PT_PHDR:
				pt_pdhr_forbidden = true;
				break;
		}

		if(phdr.p_type == PT_INTERP && pt_interp_forbidden) {
			return -1;
		}

		if(phdr.p_type == PT_PHDR && pt_phdr_forbidden) {
			return -1;
		}

		err = elfloader_load_program_header(vm, bin, phdr, buf);
		if(err) {
			return err;
		}
		
		int pages = (phdr.p_memsz / 0x1000) + 1;
		for(int page = 0; page < pages; page++) {
			void *host_physical_p = buf + (page * 0x1000);
			err = kvm_pager_create_mapping(vm->pager, host_physical_p, phdr.p_vaddr);
			if(err) {
				return err;
			}
		}

		buf = buf + phdr.p_memsz;
	}

	return 0;
}

int elfloader_load_program_header(struct kvm_vm *vm, struct Elf_binary *bin,
		GElf_Phdr phdr, char *buf) {

		int bufsize = phdr.p_filesz < 32768 ? phdr.p_filesz : 32768;
		int remaining_bytes = phdr.p_filesz;
		int bytes = 0;
		while((bytes = read(bin->fd, buf, bufsize)) > 0) {
			remaining_bytes -= bytes;
			if(remaining_bytes < bufsize) {
				bufsize = remaining_bytes;
			}
			buf += bytes;
		}
		int bytes_diff = phdr.p_memsz - phdr.p_filesz;
		if(bytes_diff > 0) {
			memset(buf, 0, bytes_diff);
		}

		return 0;
}

int elfloader_load_section_headers(struct kvm_vm *vm, struct Elf_binary *bin) {
	return -1;
}

