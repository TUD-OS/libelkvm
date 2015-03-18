/* * libelkvm - A library that allows execution of an ELF binary inside a virtual
 * machine without a full-scale operating system
 * Copyright (C) 2013-2015 Florian Pester <fpester@os.inf.tu-dresden.de>, Björn
 * Döbel <doebel@os.inf.tu-dresden.de>,   economic rights: Technische Universitaet
 * Dresden (Germany)
 *
 * This file is part of libelkvm.
 *
 * libelkvm is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * libelkvm is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libelkvm.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <gelf.h>
#include <libelf.h>

#include <elkvm/elkvm.h>
#include <elkvm/heap.h>
#include <elkvm/region.h>

#include <memory>


namespace Elkvm {

constexpr guestptr_t loader_base_addr = 0x1000000;
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

    elf_ptr(const elf_ptr &) = delete;
    elf_ptr operator=(const elf_ptr &) = delete;

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
    bool _is_ldr;
    std::string _loader;
    guestptr_t _entry_point;
    struct Elf_auxv _auxv;

    bool is_valid_elf_kind(const elf_ptr &eptr) const;
    bool is_valid_elf_class(const elf_ptr &eptr) const;
    void initialize_interpreter(const elf_file &file, GElf_Phdr phdr);
    bool check_phdr_for_interpreter(GElf_Phdr phdr) const;
    int check_elf(const elf_file &file, const elf_ptr &eptr);
    int parse_program(const elf_file &file, const elf_ptr &eptr);
    void get_dynamic_loader(const elf_file &file, GElf_Phdr phdr);
    void load_phdr(GElf_Phdr phdr, const elf_file &file, const elf_ptr &eptr);
    int load_program_header(GElf_Phdr phdr, const Region &region, const elf_file &file,
        const elf_ptr &eptr);
    void pad_begin(GElf_Phdr phdr, const Region &region, const elf_file &file,
        const elf_ptr &eptr);
    void read_segment(GElf_Phdr phdr, const Region &region,
        const elf_file &file);
    void pad_end(GElf_Phdr phdr, const Region &region, const elf_file &file,
        const elf_ptr &eptr);
    void pad_text_begin(const Region &region, size_t padsize, const elf_ptr &eptr);
    void pad_text_end(void *host_p, size_t padsize, const elf_file &file,
       const elf_ptr &eptr);
    void pad_data_begin(const Region &region, size_t padsize, const elf_file &file,
        const elf_ptr &eptr);
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

