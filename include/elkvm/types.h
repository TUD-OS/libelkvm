#pragma once

/*
 * Basic types used by various ELKVM modules.
 */

#include <cstdint>
#include <sys/types.h>
#include <signal.h>

#include <memory>

/*
 * Guest pointer type
 */
typedef uint64_t guestptr_t;

/*
 * TODO: needs doc
 */
struct region_mapping {
  void *host_p;
  guestptr_t guest_virt;
  size_t length;
  unsigned mapped_pages;
  int prot;
  int flags;
  int fd;
  off_t offset;
};


/*
 * TODO: needs doc
 */
struct linux_dirent {
    unsigned long  d_ino;     /* Inode number */
    unsigned long  d_off;     /* Offset to next linux_dirent */
    unsigned short d_reclen;  /* Length of this linux_dirent */
    char           d_name[];  /* Filename (null-terminated) */
                              /* length is actually (d_reclen - 2 -
                                 offsetof(struct linux_dirent, d_name)) */
    /*
    char           pad;       // Zero padding byte
    char           d_type;    // File type (only since Linux
                              // 2.6.4); offset is (d_reclen - 1)
    */
};


namespace Elkvm {
class Region;


/*
 * TODO: needs doc
 */
struct elkvm_flat {
  std::shared_ptr<Elkvm::Region> region;
  uint64_t size;
};


/*
 * TODO: needs doc
 */
struct elkvm_signals {
  struct sigaction signals[_NSIG];
};
} // namespace Elkvm
