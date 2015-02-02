#pragma once

#include <gelf.h>
#include <libelf.h>

#include <elkvm/elkvm.h>
#include <elkvm/heap.h>
#include <elkvm/region.h>

#include <memory>

#define LD_LINUX_SO_BASE 0x1000000

namespace Elkvm {

struct Elf_auxv {
  uint64_t at_phdr;
  uint64_t at_phent;
  uint64_t at_phnum;
  uint64_t at_entry;
  uint64_t at_base;
  bool valid;
};

class elf_file {
  private:
    int _fd;

  public:
    elf_file(std::string pathname);
    ~elf_file();
    size_t read(char *buf, size_t bytes, off64_t off = 0) const;
    ssize_t read_segment(char *buf, size_t bytes, off64_t off) const;
    int fd() const;
};

class elf_ptr {
  private:
    Elf *_ptr;

  public:
    elf_ptr(const elf_file &file);
    ~elf_ptr();

    Elf_Kind get_elf_kind() const;
    int get_class() const;
    GElf_Ehdr get_ehdr() const;
    size_t get_phdrnum() const;
    GElf_Phdr get_phdr(unsigned i) const;
};

class ElfBinary {
  private:
    std::unique_ptr<ElfBinary> _ldr;
    std::shared_ptr<RegionManager> _rm;
    HeapManager &_hm;

    /* this needs to be a size_t because of the decl
     * of elf_getphdrnum */
    size_t _num_phdrs;
    bool _statically_linked;
    bool _shared_object;
    std::string _loader;
    guestptr_t _entry_point;
    struct Elf_auxv _auxv;

    bool is_valid_elf_kind(const elf_ptr &eptr) const;
    bool is_valid_elf_class(const elf_ptr &eptr) const;
    void initialize_interpreter(const elf_file &file, GElf_Phdr phdr);
    bool check_phdr_for_interpreter(GElf_Phdr phdr) const;
    int check_elf(const elf_file &file, const elf_ptr &eptr, bool is_ldr);
    int parse_program(const elf_file &file, const elf_ptr &eptr);
    void get_dynamic_loader(const elf_file &file, GElf_Phdr phdr);
    void load_phdr(GElf_Phdr phdr, const elf_file &file, const elf_ptr &eptr);
    int load_program_header(GElf_Phdr phdr, std::shared_ptr<Region> region,
        const elf_file &file, const elf_ptr &eptr);
    void pad_begin(GElf_Phdr phdr, std::shared_ptr<Region> region,
        const elf_file &file, const elf_ptr &eptr);
    void read_segment(GElf_Phdr phdr, std::shared_ptr<Region> region,
        const elf_file &file);
    void pad_end(GElf_Phdr phdr, std::shared_ptr<Region> region,
        const elf_file &file, const elf_ptr &eptr);
    void pad_text_begin(std::shared_ptr<Region> region, size_t padsize,
        const elf_ptr &eptr);
    void pad_text_end(void *host_p, size_t padsize, const elf_file &file,
       const elf_ptr &eptr);
    void pad_data_begin(std::shared_ptr<Region> region, size_t padsize,
        const elf_file &file, const elf_ptr &eptr);
    void load_dynamic();
    GElf_Phdr text_header;
    GElf_Phdr find_header(const elf_ptr &eptr, unsigned flags);
    GElf_Phdr find_data_header(const elf_ptr &eptr);
    GElf_Phdr find_text_header(const elf_ptr &eptr);

  public:
    ElfBinary(std::string pathname, std::shared_ptr<RegionManager> rm,
        HeapManager &hm, bool is_ldr = false);

    ElfBinary(ElfBinary const&) = delete;
    ElfBinary& operator=(ElfBinary const&) = delete;

    int load_binary(std::string pathname);
    guestptr_t get_entry_point();
    const struct Elf_auxv &get_auxv() const;
    bool is_dynamically_linked() const;
    std::string get_loader() const;
};

ptopt_t get_pager_opts_from_phdr_flags(int flags);

//namespace Elkvm
}

