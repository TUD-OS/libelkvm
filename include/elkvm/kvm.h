#pragma once

#define KVM_EXPECT_VERSION 12
#define KVM_DEV_PATH "/dev/kvm"

namespace Elkvm {
struct elkvm_opts {
	int argc;
	char **argv;
	char **environ;
	int fd;
	int run_struct_size;
  bool debug;
};
} // namespace Elkvm

int elkvm_init(Elkvm::elkvm_opts *, int, char **, char **);
int elkvm_cleanup(Elkvm::elkvm_opts *);
