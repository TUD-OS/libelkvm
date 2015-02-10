#pragma once

#include <memory>

#include <elkvm/mapping.h>

namespace Elkvm {

  class Region {
    private:
      void *host_p;
      guestptr_t addr;
      size_t rsize;
      bool free;
      std::string name;

    public:
      Region(void *chunk_p, size_t size, const std::string &title="anon region",
          bool f = true) :
        host_p(chunk_p),
        addr(0),
        rsize(size),
        free(f),
        name(title)
    {}

	  Region(const Region&) = delete;
	  Region& operator=(const Region&) = delete;

      void *base_address() const { return host_p; }
      struct elkvm_memory_region *c_region() const;
      bool contains_address(const void *addr) const;
      bool contains_address(guestptr_t addr) const;
      off64_t offset_in_region(guestptr_t addr) const;
      size_t space_after_address(const void * const) const;
      guestptr_t guest_address() const { return addr; }
      bool is_free() const { return free; }
      void *last_valid_address() const;
      guestptr_t last_valid_guest_address() const;
      void set_free() { free = true; addr = 0x0; }
      void set_guest_addr(guestptr_t a) { addr = a; };
      void set_used() { free = false; }
      size_t size() const { return rsize; }
      std::shared_ptr<Region> slice_begin(const size_t size,
          const std::string &purpose="anon region");
      std::pair<std::shared_ptr<Region>, std::shared_ptr<Region>>
        slice_center(off_t off, size_t len);
      std::string const& getName() const { return this->name; }
  };

  std::ostream &print(std::ostream &, const Region &);
  bool operator==(const Region &, const Region &);

//namespace Elkvm
}

