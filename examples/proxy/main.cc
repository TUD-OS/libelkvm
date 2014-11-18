#include <cstring>
#include <elkvm/elkvm.h>
#include <elkvm/kvm.h>

#include <stdint.h>

extern char **environ;
Elkvm::elkvm_opts elkvm;
bool inspect;

void print_usage(char **argv) {
  printf("Usage: %s [-d] [-s] binary [binaryopts]\n", argv[0]);
  exit(EXIT_FAILURE);
}

extern char *optarg;
extern int optind;
extern int opterr;

int main(int argc, char **argv) {

  int opt;
  int err;
  int debug = 0;
  int gdb = 0;
  int myopts = 1;
  opterr = 0;

  while((opt = getopt(argc, argv, "+dD")) != -1) {
    switch(opt) {
      case 'd':
        debug = 1;
        myopts++;
        break;
      case 'D':
        gdb = 1;
        myopts++;
        break;
    }
  }

  if(optind >= argc) {
    print_usage(argv);
  }

  char *binary = argv[myopts];
  char **binargv = &argv[myopts];
  int binargc = argc - myopts;

  err = elkvm_init(&elkvm, binargc, binargv, environ);
  if(err) {
    if(errno == -ENOENT) {
      printf("/dev/kvm seems not to exist. Check your KVM installation!\n");
    }
    if(errno == -EACCES) {
      printf("Access to /dev/kvm was denied. Check if you belong to the 'kvm' group!\n");
    }
    printf("ERROR initializing VM errno: %i Msg: %s\n", -err, strerror(-err));
    return -1;
  }

  std::shared_ptr<Elkvm::VM> vm = elkvm_vm_create(&elkvm, binary);
  if(vm == nullptr) {
    printf("ERROR creating VM: %i\n", errno);
    printf("  Msg: %s\n", strerror(errno));
    return EXIT_FAILURE;
  }

  if(debug) {
    vm->set_debug(true);
    if(err) {
      printf("ERROR putting VM in debug mode errno: %i Msg: %s\n", -err, strerror(-err));
      return -1;
    }
  }

  if(gdb) {
    //gdbstub will take it from here!
    elkvm_gdbstub_init(vm);
    return 0;
  }

  err = vm->run();
  if(err) {
    printf("ERROR running VCPU errno: %i Msg: %s\n", -err, strerror(-err));
    return -1;
  }

  err = elkvm_cleanup(&elkvm);
  if(err) {
    printf("ERROR cleaning up errno: %i Msg: %s\n", -err, strerror(-err));
    return -1;
  }

  printf("DONE\n");
  return 0;
}

