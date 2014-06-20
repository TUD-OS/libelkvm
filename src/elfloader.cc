#include <cstring>

#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "elfloader.h"
#include <elkvm.h>
#include <kvm.h>
#include <heap.h>
#include <pager.h>
#include <region.h>
#include <vcpu.h>

namespace Elkvm {
  ElfBinary binary;
  extern RegionManager rm;
  extern HeapManager heap_m;

  int ElfBinary::load_binary(std::string pathname) {
    if(pathname.empty()) {
      return -EIO;
    }

    if(pager->system_chunk.userspace_addr == 0) {
      return -EIO;
    }

    auxv.at_base = 0x0;

    fd = open(pathname.c_str(), O_RDONLY);
    if(fd < 1) {
      return -errno;
    }

    if(elf_version(EV_CURRENT) == EV_NONE) {
      return -EIO;
    }

    e = elf_begin(fd, ELF_C_READ, NULL);
    if(e == NULL) {
      return -ENOMEM;
    }

    int err = check_elf();
    if(err) {
      goto out_close;
    }

    err = parse_program();
    if(!statically_linked) {
      err = load_dynamic();
      /* we need to mark the binary as dynamic again, because this is overwritten
       * by the dynamic loader, which is always statically linked */
      statically_linked = false;
    }

out_close:
    elf_end(e);
    close(fd);

    return err;

  }

  guestptr_t ElfBinary::get_entry_point() {
    return shared_object ? auxv.at_base + entry_point : entry_point;
  }

  int ElfBinary::check_elf() {
    Elf_Kind ek = elf_kind(e);
    switch(ek) {
      /* only deal with elf binaries for now */
      case ELF_K_ELF:
        break;
      case ELF_K_AR:
      case ELF_K_NONE:
      default:
        return -EINVAL;
    }

    /* for now process only 64bit ELF files */
    elfclass = gelf_getclass(e);
    switch(elfclass) {
      case ELFCLASS64:
        break;
      case ELFCLASSNONE:
      case ELFCLASS32:
      default:
        return -EINVAL;
    }

    GElf_Ehdr ehdr;
    if(gelf_getehdr(e, &ehdr) == NULL) {
      return -EIO;
    }

    shared_object = (ehdr.e_type == ET_DYN);
    entry_point = ehdr.e_entry;
    int err = elf_getphdrnum(e, &num_phdrs);
    if(err) {
      return -err;
    }

    statically_linked = true;
    for(unsigned i = 0; i < num_phdrs; i++) {
      GElf_Phdr phdr;
      gelf_getphdr(e, i, &phdr);

      /* a program header's memsize may be larger than or equal to its filesize */
      if(phdr.p_filesz > phdr.p_memsz) {
        return -EIO;
      }

      switch(phdr.p_type) {
        case PT_INTERP:
          statically_linked = false;
          get_dynamic_loader(phdr);
          break;
      }
      if(!statically_linked) {
        auxv.valid = true;
        auxv.at_entry = entry_point;
        auxv.at_phnum = num_phdrs;
        auxv.at_phent = ehdr.e_phentsize;
        break;
      }
    }

    return 0;
  }


  void ElfBinary::get_dynamic_loader(GElf_Phdr phdr) {
    int off = lseek(fd, phdr.p_offset, SEEK_SET);
    assert(off >= 0);

    /* TODO make this nicer */
    char *l = (char *)malloc(PATH_MAX);
    assert(l != nullptr);

    size_t bytes = read(fd, l, phdr.p_memsz);
    assert(bytes == phdr.p_memsz && "short read on dynamic loader location");

    loader = l;
  }

  int ElfBinary::parse_program() {
    bool pt_interp_forbidden = false;
    bool pt_phdr_forbidden = false;

    for(unsigned i = 0; i < num_phdrs; i++) {
      GElf_Phdr phdr;
      gelf_getphdr(e, i, &phdr);

      /* a program header's memsize may be larger than or equal to its filesize */
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
            return -EINVAL;
          }
          pt_interp_forbidden = true;
          break;
        case PT_LOAD:
          pt_interp_forbidden = true;
          pt_phdr_forbidden = true;
          load_phdr(phdr);
          break;
        case PT_PHDR:
          auxv.at_phdr = phdr.p_vaddr;
          if(pt_phdr_forbidden) {
            return -EINVAL;
          }
          pt_phdr_forbidden = true;
          break;
      }

    }

    return 0;
  }

  void ElfBinary::load_phdr(GElf_Phdr phdr) {
    guestptr_t load_addr = phdr.p_vaddr;
    if(shared_object && phdr.p_vaddr == 0x0) {
      load_addr = auxv.at_base = LD_LINUX_SO_BASE;
    } else if(auxv.at_base > 0x0) {
      load_addr = auxv.at_base + phdr.p_vaddr;
    }

    size_t total_size = phdr.p_memsz + offset_in_page(load_addr);
    std::shared_ptr<Region> loadable_region = Elkvm::rm.allocate_region(total_size);
    loadable_region->set_guest_addr(page_begin(load_addr));

    int err = load_program_header(phdr, loadable_region);
    assert(err == 0 && "Error in ElfBinary::load_program_header");

    ptopt_t opts = 0;
    if(phdr.p_flags & PF_X) {
      opts |= PT_OPT_EXEC;
    }
    if(phdr.p_flags & PF_W) {
      opts |= PT_OPT_WRITE;
    }

    int pages = pages_from_size(total_size);
    err = elkvm_pager_map_region(pager, loadable_region->base_address(),
        loadable_region->guest_address(), pages, opts);
    assert(err == 0 && "could not create pt entries for loadable region");

    if(phdr.p_flags & PF_W) {
      /* writable region should be data */
      err = heap_m.init(loadable_region, total_size);
      assert(err == 0 && "Error initializing heap");
    }
  }

  int ElfBinary::load_program_header(GElf_Phdr phdr, std::shared_ptr<Region> region) {
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

  if(!page_aligned((uint64_t)region->base_address())) {
    return -EIO;
  }

  pad_begin(phdr, region);
  read_segment(phdr, region);
  pad_end(phdr, region);

  return 0;
  }

  void ElfBinary::pad_begin(GElf_Phdr phdr, std::shared_ptr<Region> region) {
    size_t padsize = offset_in_page(phdr.p_vaddr);

    if(padsize) {
      if(phdr.p_flags & PF_X) {
        /* executable segment should be text */
        pad_text_begin(region, padsize);
        return;
      } else if(phdr.p_flags & PF_W) {
        /* writeable segment should be data */
        pad_data_begin(region, padsize);
        return;
      }

      /* this should never happen */
      assert(false && "pad_begin should only be called with data or text sections");
    }
  }

  void ElfBinary::pad_end(GElf_Phdr phdr, std::shared_ptr<Region> region) {
    void *host_p = (char *)region->base_address() + offset_in_page(phdr.p_vaddr) + phdr.p_filesz;
    size_t padsize = page_remain((uint64_t)host_p);

    if(phdr.p_flags & PF_X) {
      /* executable segment should be text */
      pad_text_end(host_p, padsize);
      return;
    }
    if(phdr.p_flags & PF_W) {
      padsize += (phdr.p_memsz - phdr.p_filesz);
      /* set uninitialized data to 0s */
      memset(host_p, 0, padsize);
      return;
    }

    /* this should never happen */
    assert(false);
  }

  void ElfBinary::read_segment(GElf_Phdr phdr, std::shared_ptr<Region> region) {
    char *buf = (char *)region->base_address() + offset_in_page(phdr.p_vaddr);

    /*
     * make sure we are going to read full pages
     */
    int remaining_bytes = phdr.p_filesz;
    int bufsize = remaining_bytes < 32768 ? remaining_bytes : 32768;

    int bytes = 0;

    int off = lseek(fd, phdr.p_offset, SEEK_SET);
    assert(off >= 0 && "could not seek in file");

    while((bytes = read(fd, buf, bufsize)) > 0) {
      remaining_bytes -= bytes;
      if(remaining_bytes < bufsize) {
        bufsize = remaining_bytes;
      }
      buf += bytes;
    }
  }

  void ElfBinary::pad_text_begin(std::shared_ptr<Region> region, size_t padsize) {
    assert(e != nullptr);
    assert(region->base_address() != nullptr);

    GElf_Ehdr ehdr;
    gelf_getehdr(e, &ehdr);

    memcpy(region->base_address(), &ehdr, padsize);
  }

  void ElfBinary::pad_data_begin(std::shared_ptr<Region> region, size_t padsize) {
    text_header = find_text_header();

    uint64_t text_end = text_header.p_offset + text_header.p_filesz;

    if(text_end > padsize) {
      int off = lseek(fd, text_end - padsize - 1, SEEK_SET);
      assert(off >= 0 && "seek on binary failed");

      size_t bytes = read(fd, region->base_address(), padsize);
      assert(bytes == padsize && "short read on file");
    } else {
      memset(region->base_address(), 0, padsize);
    }
  }

  void ElfBinary::pad_text_end(void *host_p, size_t padsize) {
    /*
     * find the first page of the data segment and pad the remainder of the
     * last page of text with its contents
     */

    GElf_Phdr data_header = find_data_header();

    int off = lseek(fd, data_header.p_offset, SEEK_SET);
    assert(off >= 0 && "seek in binary failed");

    size_t bytes = read(fd, host_p, padsize);
    assert(bytes == padsize);
  }

  GElf_Phdr ElfBinary::find_data_header() {
    GElf_Phdr phdr;
    for(unsigned i = 0; i < num_phdrs; i++) {
      gelf_getphdr(e, i, &phdr);

      if(phdr.p_type == PT_LOAD &&
          phdr.p_flags & PF_W) {
        return phdr;
      }
    }

    /* every elf file should have a data header */
    assert(false && "every elf file should have a data header");
    return phdr;
  }

  GElf_Phdr ElfBinary::find_text_header() {
    GElf_Phdr phdr;
    for(unsigned i = 0; i < num_phdrs; i++) {
      gelf_getphdr(e, i, &phdr);

      if(phdr.p_type == PT_LOAD &&
          phdr.p_flags & PF_X) {
        return phdr;
      }
    }

    /* every elf file should have a text header */
    assert(false && "every elf file should have a text header");
    return phdr;
  }

  int ElfBinary::load_dynamic() {
    //TODO add ld.so to arguments on stack!
    return binary.load_binary(loader);
  }

  const struct Elf_auxv &ElfBinary::get_auxv() {
    return auxv;
  }

//namespace Elkvm
}


#ifdef __cplusplus
extern "C" {
#endif

int elkvm_load_binary(const char *b, struct kvm_pager *pager) {
  assert(pager != nullptr);
  Elkvm::binary.init(pager);
  //moved to ElfBinary constructor
  return Elkvm::binary.load_binary(b);
}

guestptr_t elkvm_loader_get_entry_point() {
  return Elkvm::binary.get_entry_point();
}

#ifdef __cplusplus
}
#endif

