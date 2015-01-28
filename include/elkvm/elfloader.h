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

class ElfBinary {
  private:
    std::unique_ptr<ElfBinary> ldr;
    std::shared_ptr<RegionManager> _rm;
    HeapManager &_hm;

    int fd;
    Elf *e;
    size_t num_phdrs;
    bool statically_linked;
    bool shared_object;
    int elfclass;
    std::string loader;
    guestptr_t entry_point;
    struct Elf_auxv auxv;

    int check_elf(bool is_ldr);
    int parse_program();
    void get_dynamic_loader(GElf_Phdr phdr);
    void load_phdr(GElf_Phdr phdr);
    int load_program_header(GElf_Phdr phdr, std::shared_ptr<Region> region);
    void pad_begin(GElf_Phdr phdr, std::shared_ptr<Region> region);
    void read_segment(GElf_Phdr phdr, std::shared_ptr<Region> region);
    void pad_end(GElf_Phdr phdr, std::shared_ptr<Region> region);
    void pad_text_begin(std::shared_ptr<Region> region, size_t padsize);
    void pad_text_end(void *host_p, size_t padsize);
    void pad_data_begin(std::shared_ptr<Region> region, size_t padsize);
    void load_dynamic();
    GElf_Phdr text_header;
    GElf_Phdr find_data_header();
    GElf_Phdr find_text_header();

  public:
    ElfBinary(std::string pathname, std::shared_ptr<RegionManager> rm,
        HeapManager &hm, bool is_ldr = false);

    ElfBinary(ElfBinary const&) = delete;
    ElfBinary& operator=(ElfBinary const&) = delete;

    int load_binary(std::string pathname);
    guestptr_t get_entry_point();
    const struct Elf_auxv &get_auxv() const;
    bool is_dynamically_linked() const { return !statically_linked; }
    std::string get_loader() const { return loader; }
};

ptopt_t get_pager_opts_from_phdr_flags(int flags);

//namespace Elkvm
}

