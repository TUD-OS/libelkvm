#include <cstring>
#include <memory>

#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <elkvm/elfloader.h>
#include <elkvm/elkvm.h>
#include <elkvm/elkvm-internal.h>
#include <elkvm/kvm.h>
#include <elkvm/heap.h>
#include <elkvm/pager.h>
#include <elkvm/region.h>
#include <elkvm/region_manager.h>

namespace Elkvm {
  class VCPU;

  elf_file::elf_file(std::string pathname) {
    _fd = open(pathname.c_str(), O_RDONLY);
    if(_fd < 1) {
      throw;
    }
  }

  elf_file::~elf_file() {
    close(_fd);
  }

  int elf_file::fd() const {
    return _fd;
  }

  size_t elf_file::read(char *buf, size_t bytes, off64_t off) const {
    int toff = lseek(_fd, off, SEEK_SET);
    assert(toff == off);

    size_t read_bytes = ::read(_fd, buf, bytes);
    assert(read_bytes == bytes && "short read on file");
    return read_bytes;
  }

  ssize_t elf_file::read_segment(char *buf, size_t bytes, off64_t off) const {
    /* make sure we are going to read full pages */
    constexpr size_t max_bufsize = 0x8000;
    auto bufsize = bytes < max_bufsize ? bytes : max_bufsize;

    int toff = lseek(_fd, off, SEEK_SET);
    assert(off == toff && "could not seek in file");

    size_t remaining_bytes = bytes;
    ssize_t read_bytes = 0;
    while((read_bytes = ::read(_fd, buf, bufsize)) > 0) {
      remaining_bytes -= read_bytes;
      if(remaining_bytes < bufsize) {
        bufsize = remaining_bytes;
      }
      buf += read_bytes;
    }
    assert(remaining_bytes == 0);

    return read_bytes;
  }

  ElfBinary::ElfBinary(std::string pathname, std::shared_ptr<RegionManager> rm,
      HeapManager &hm, bool is_ldr) :
    _ldr(nullptr),
    _rm(rm),
    _hm(hm),
    _elf_ptr(0),
    _num_phdrs(0),
    _statically_linked(false),
    _shared_object(false),
    _loader("undefined ldr"),
    _entry_point(~0ULL),
    _auxv(),
    text_header()
  {
    assert(!pathname.empty() && "cannot load binary from empty pathname");
    elf_file file(pathname);

    _auxv.valid = is_ldr;
    _auxv.at_base = 0x0;

    if(elf_version(EV_CURRENT) == EV_NONE) {
      throw;
    }

    _elf_ptr = elf_begin(file.fd(), ELF_C_READ, NULL);
    if(_elf_ptr == nullptr) {
      throw;
    }

    int err = check_elf(file, is_ldr);
    if(err) {
      throw;
    }

    if(_statically_linked) {
      err = parse_program(file);
    } else {
      load_dynamic();
    }

    elf_end(_elf_ptr);
    if(err) {
      throw;
    }
  }

  guestptr_t ElfBinary::get_entry_point() {
    if(_statically_linked) {
      return _shared_object ? _auxv.at_base + _entry_point : _entry_point;
    } else {
      return _ldr->get_entry_point();
    }
  }

  bool ElfBinary::is_valid_elf_kind(Elf *e) const {
    Elf_Kind ek = elf_kind(e);
    switch(ek) {
      /* only deal with elf binaries for now */
      case ELF_K_ELF:
        return true;
      case ELF_K_AR:
      case ELF_K_NONE:
      default:
        return false;
    }
  }

  bool ElfBinary::is_valid_elf_class(Elf *e) const {
    /* for now process only 64bit ELF files */
    auto elfclass = gelf_getclass(e);
    switch(elfclass) {
      case ELFCLASS64:
        return true;
      case ELFCLASSNONE:
      case ELFCLASS32:
      default:
        return false;
    }
  }

  void ElfBinary::initialize_interpreter(const elf_file &file, GElf_Phdr phdr) {
    _statically_linked = false;
    get_dynamic_loader(file, phdr);
  }

  bool ElfBinary::check_phdr_for_interpreter(GElf_Phdr phdr) const {
    /* a program header's memsize may be larger than or equal to its filesize */
    if(phdr.p_filesz > phdr.p_memsz) {
      throw;
    }

    switch(phdr.p_type) {
      case PT_INTERP:
        return true;
    }
    return false;
  }

  int ElfBinary::check_elf(const elf_file &file, bool is_ldr) {
    if(!is_valid_elf_kind(_elf_ptr) || !is_valid_elf_class(_elf_ptr)) {
      return -EINVAL;
    }

    GElf_Ehdr ehdr;
    if(gelf_getehdr(_elf_ptr, &ehdr) == NULL) {
      return -EIO;
    }

    _shared_object = (ehdr.e_type == ET_DYN);
    _entry_point = ehdr.e_entry;
    int err = elf_getphdrnum(_elf_ptr, &_num_phdrs);
    if(err) {
      return -err;
    }

    for(unsigned i = 0; i < _num_phdrs; i++) {
      GElf_Phdr phdr;
      gelf_getphdr(_elf_ptr, i, &phdr);
      _statically_linked = !check_phdr_for_interpreter(phdr);
      if(!_statically_linked) {
        initialize_interpreter(file, phdr);
        break;
      }
    }
    if(is_ldr) {
      _auxv.valid = true;
      _auxv.at_entry = _entry_point;
      _auxv.at_phnum = _num_phdrs;
      _auxv.at_phent = ehdr.e_phentsize;
    }

    return 0;
  }


  void ElfBinary::get_dynamic_loader(const elf_file &file, GElf_Phdr phdr) {
    /* TODO make this nicer */
    char *l = (char *)malloc(PATH_MAX);
    assert(l != nullptr);

    file.read(l, phdr.p_memsz, phdr.p_offset);
    _loader = l;
  }

  int ElfBinary::parse_program(const elf_file &file) {
    bool pt_interp_forbidden = false;
    bool pt_phdr_forbidden = false;

    for(unsigned i = 0; i < _num_phdrs; i++) {
      GElf_Phdr phdr;
      gelf_getphdr(_elf_ptr, i, &phdr);

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
          load_phdr(phdr, file);
          break;
        case PT_PHDR:
          _auxv.at_phdr = phdr.p_vaddr;
          if(pt_phdr_forbidden) {
            return -EINVAL;
          }
          pt_phdr_forbidden = true;
          break;
      }

    }

    return 0;
  }

  void ElfBinary::load_phdr(GElf_Phdr phdr, const elf_file &file) {
    guestptr_t load_addr = phdr.p_vaddr;
    if(_shared_object && phdr.p_vaddr == 0x0) {
      load_addr = _auxv.at_base = LD_LINUX_SO_BASE;
    } else if(_auxv.at_base > 0x0) {
      load_addr = _auxv.at_base + phdr.p_vaddr;
    }

    size_t total_size = phdr.p_memsz + offset_in_page(load_addr);
    std::shared_ptr<Region> loadable_region =
      _rm->allocate_region(total_size, "ELF PHdr");
    loadable_region->set_guest_addr(page_begin(load_addr));

    int err = load_program_header(phdr, loadable_region, file);
    assert(err == 0 && "Error in ElfBinary::load_program_header");

    ptopt_t opts = get_pager_opts_from_phdr_flags(phdr.p_flags);

    int pages = pages_from_size(total_size);
    err = _rm->get_pager().map_region(loadable_region->base_address(),
        loadable_region->guest_address(), pages, opts);
    assert(err == 0 && "could not create pt entries for loadable region");

    if(phdr.p_flags & PF_W) {
      /* writable region should be data */
      err = _hm.init(loadable_region, total_size);
      assert(err == 0 && "Error initializing heap");
    }
  }

  int ElfBinary::load_program_header(GElf_Phdr phdr, std::shared_ptr<Region> region,
      const elf_file &file) {
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

  if(!page_aligned<guestptr_t>((uint64_t)region->base_address())) {
    return -EIO;
  }

  pad_begin(phdr, region, file);
  read_segment(phdr, region, file);
  pad_end(phdr, region, file);

  return 0;
  }

  void ElfBinary::pad_begin(GElf_Phdr phdr, std::shared_ptr<Region> region,
      const elf_file &file) {
    size_t padsize = offset_in_page(phdr.p_vaddr);

    if(padsize) {
      if(phdr.p_flags & PF_X) {
        /* executable segment should be text */
        pad_text_begin(region, padsize);
        return;
      } else if(phdr.p_flags & PF_W) {
        /* writeable segment should be data */
        pad_data_begin(region, padsize, file);
        return;
      }

      /* this should never happen */
      assert(false && "pad_begin should only be called with data or text sections");
    }
  }

  void ElfBinary::pad_end(GElf_Phdr phdr, std::shared_ptr<Region> region,
      const elf_file &file) {
    void *host_p = (char *)region->base_address() + offset_in_page(phdr.p_vaddr) + phdr.p_filesz;
    size_t padsize = page_remain((uint64_t)host_p);

    if(phdr.p_flags & PF_X) {
      /* executable segment should be text */
      pad_text_end(host_p, padsize, file);
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

  void ElfBinary::read_segment(GElf_Phdr phdr, std::shared_ptr<Region> region,
      const elf_file &file) {
    char *buf = static_cast<char *>(region->base_address())
      + offset_in_page(phdr.p_vaddr);
    file.read_segment(buf, phdr.p_filesz, phdr.p_offset);
  }

  void ElfBinary::pad_text_begin(std::shared_ptr<Region> region, size_t padsize) {
    assert(_elf_ptr != nullptr);
    assert(region->base_address() != nullptr);

    GElf_Ehdr ehdr;
    gelf_getehdr(_elf_ptr, &ehdr);

    memcpy(region->base_address(), &ehdr, padsize);
  }

  void ElfBinary::pad_data_begin(std::shared_ptr<Region> region, size_t padsize,
      const elf_file &file) {
    text_header = find_text_header();

    uint64_t text_end = text_header.p_offset + text_header.p_filesz;

    if(text_end > padsize) {
      file.read(static_cast<char *>(region->base_address()), padsize,
          text_end - padsize - 1);
    } else {
      memset(region->base_address(), 0, padsize);
    }
  }

  void ElfBinary::pad_text_end(void *host_p, size_t padsize, const elf_file &file) {
    /*
     * find the first page of the data segment and pad the remainder of the
     * last page of text with its contents
     */
    GElf_Phdr data_header = find_data_header();
    file.read(static_cast<char *>(host_p), padsize, data_header.p_offset);
  }

  GElf_Phdr ElfBinary::find_data_header() {
    GElf_Phdr phdr;
    for(unsigned i = 0; i < _num_phdrs; i++) {
      gelf_getphdr(_elf_ptr, i, &phdr);

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
    for(unsigned i = 0; i < _num_phdrs; i++) {
      gelf_getphdr(_elf_ptr, i, &phdr);

      if(phdr.p_type == PT_LOAD &&
          phdr.p_flags & PF_X) {
        return phdr;
      }
    }

    /* every elf file should have a text header */
    assert(false && "every elf file should have a text header");
    return phdr;
  }

  void ElfBinary::load_dynamic() {
    _ldr = std::unique_ptr<ElfBinary>(new ElfBinary(_loader, _rm, _hm, true));
  }

  const struct Elf_auxv &ElfBinary::get_auxv() const {
    if(_ldr != nullptr) {
      return _ldr->get_auxv();
    }

    return _auxv;
  }

  bool ElfBinary::is_dynamically_linked() const {
    return !_statically_linked;
  }

  std::string ElfBinary::get_loader() const {
    return _loader;
  }

  ptopt_t get_pager_opts_from_phdr_flags(int flags) {
    ptopt_t opts = 0;
    if(flags & PF_X) {
      opts |= PT_OPT_EXEC;
    }
    if(flags & PF_W) {
      opts |= PT_OPT_WRITE;
    }
    return opts;
  }

//namespace Elkvm
}

