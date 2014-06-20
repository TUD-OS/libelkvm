#pragma once

#include <gelf.h>
#include <libelf.h>

#include "elkvm.h"
#include "region.h"

#include <memory>

#define LD_LINUX_SO_BASE 0x7FFFF0000000

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
    struct kvm_pager * pager;
    int fd;
    Elf *e;
    size_t num_phdrs;
    bool statically_linked;
    bool shared_object;
    int elfclass;
    std::string loader;
    guestptr_t entry_point;
    struct Elf_auxv auxv;

    int check_elf();
    int parse_program();
    int set_entry_point();
    void get_dynamic_loader(GElf_Phdr phdr);
    void load_phdr(GElf_Phdr phdr);
    int load_program_header(GElf_Phdr phdr, std::shared_ptr<Region> region);
    void pad_begin(GElf_Phdr phdr, std::shared_ptr<Region> region);
    void read_segment(GElf_Phdr phdr, std::shared_ptr<Region> region);
    void pad_end(GElf_Phdr phdr, std::shared_ptr<Region> region);
    void pad_text_begin(std::shared_ptr<Region> region, size_t padsize);
    void pad_text_end(void *host_p, size_t padsize);
    void pad_data_begin(std::shared_ptr<Region> region, size_t padsize);
    int load_dynamic();
    GElf_Phdr text_header;
    GElf_Phdr find_data_header();
    GElf_Phdr find_text_header();

  public:
    ElfBinary() { auxv.valid = false; }
    void init(struct kvm_pager * p) { pager = p; }
    int load_binary(std::string pathname);
    guestptr_t get_entry_point();
};

//namespace Elkvm
}

