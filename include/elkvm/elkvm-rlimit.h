#pragma once

#include <memory>

#include <sys/time.h>
#include <sys/resource.h>

namespace Elkvm {

class rlimit {
  private:
    std::array<struct ::rlimit, RLIMIT_NLIMITS> _rlimits;

  public:
    rlimit();
    const struct ::rlimit *get(int i) const;
    void set(int i, const struct ::rlimit *val);
};

//namespace Elkvm
}
