#include <fstream>
#include <cstring>
#include <elkvm/elkvm.h>
#include <elkvm/elkvm-log.h>
#include <elkvm/kvm.h>
#include <cassert>

#include <stdint.h>
#include <smmintrin.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <unistd.h>

extern char **environ;
Elkvm::elkvm_opts elkvm;
bool inspect;

void print_usage(char **argv) {
  printf("Usage: %s [-d] binary [binaryopts]\n", argv[0]);
  printf("       %s [-d] -a <PID>\n", argv[0]);
  exit(EXIT_FAILURE);
}

extern char *optarg;
extern int optind;
extern int opterr;

std::shared_ptr<Elkvm::VM> run_new(int argc, char **argv, int myopts)
{
  char *binary = argv[myopts];
  char **binargv = &argv[myopts];
  int binargc = argc - myopts;

  int err = elkvm_init(&elkvm, binargc, binargv, environ);
  if(err) {
    if(errno == -ENOENT) {
      printf("/dev/kvm seems not to exist. Check your KVM installation!\n");
    }
    if(errno == -EACCES) {
      printf("Access to /dev/kvm was denied. Check if you belong to the 'kvm' group!\n");
    }
    printf("ERROR initializing VM errno: %i Msg: %s\n", -err, strerror(-err));
    abort();
  }

  std::shared_ptr<Elkvm::VM> vm = elkvm_vm_create(&elkvm, binary);
  if(vm == nullptr) {
    printf("ERROR creating VM: %i\n", errno);
    printf("  Msg: %s\n", strerror(errno));
    abort();
  }

  return vm;
}

enum {
  NAMEBUFSIZE = 256,
};

/*
 * Stop a process by attaching with ptrace().
 */
static bool
stop_pid(int pid)
{
    long err = ptrace(PTRACE_ATTACH, pid, 0, 0);
    if (err) {
        perror("ptrace attach");
        return false;
    }

    /*
     * Now we have to wait until the process is stopped with
     * SIGSTOP. In the meantime other signals may precede and
     * need to be reinjected into the target.
     */
    int status = 0;
    do {
        err = waitpid(pid, &status, 0);
        if (err == -1) {
          perror("waitpid");
        }
        if (WSTOPSIG(status) != SIGSTOP) {
            INFO() << "Not stopped. Injecting signal " << WSTOPSIG(status);
            err = ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(status));
            if (err) {
              perror("ptrace continue");
            }
        }
    } while (!WIFSTOPPED(status));

    INFO() << "Halted PID " << pid;
    return true;
}

/*
 * Determine the binary that is executed in process PID.
 */
void binary_for_pid(int pid, char **binary)
{
  /*
   * General idea: read /proc/<pid>/exe to determine the
   * running binary.
   */
  std::stringstream exe;
  struct stat statbuf;

  exe << "/proc/" << pid << "/exe";
  INFO() << exe.str();

  int err = lstat(exe.str().c_str(), &statbuf);
  if (err) {
    perror("stat");
    return;
  }

  if (not S_ISLNK(statbuf.st_mode)) {
    INFO() << "This is not a symlink.";
    return;
  }

  char *buf = new char[NAMEBUFSIZE];
  err = readlink(exe.str().c_str(), buf, NAMEBUFSIZE-1); // leave on byte for terminating 0
  if (err == -1) {
    perror("readlink");
    return;
  }
  assert(err < NAMEBUFSIZE);
  buf[err] = 0;

  *binary = buf;
}

struct Permissions
{
    bool readable;
    bool writable;
    bool exec;

    void init(char const *str) {
        assert(strlen(str) > 3); // at least r, w, x chars
        if (str[0] == 'r')
            readable = true;
        if (str[1] == 'w')
            writable = true;
        if (str[2] == 'x')
            exec = true;
    }

    Permissions(char const* str)
        : readable(false), writable(false), exec(false)
    { init(str); }
};

struct Mapping
{
    guestptr_t  start;
    guestptr_t  end;
    Permissions perm;

    size_t size() const
    {
        return end - start;
    }

    Mapping(guestptr_t _start, guestptr_t _end, char const *_perm)
        : start(_start), end(_end), perm(_perm)
    { }
};

/*
 * Figure out which memory regions are mapped in process PID.
 */
static void
memory_map_for_pid(int pid, std::list<Mapping>& regions)
{
  /*
   * Approach: parse /proc/<pid>/maps.
   */
  std::stringstream map;
  map << "/proc/" << pid << "/maps";
  INFO() << "Parsing regions in " << map.str();

  std::ifstream mapfile(map.str());
  if (!mapfile.good()) {
      INFO() << "Error opening map file";
  }

  do {
      guestptr_t start, stop;
      std::string perms;
      char dummy[256];

      mapfile >> std::hex >> start;
      mapfile >> dummy[0];
      mapfile >> std::hex >> stop;
      mapfile >> perms;
      mapfile.getline(dummy, 256);
      //INFO() << std::hex << start << " -- " << stop << "(" << perms << ")";
      mapfile.peek(); // peek another char to find potential EOF

      regions.emplace_back(start, stop, perms.c_str());
  } while (!mapfile.eof());

  INFO() << "Found " << regions.size() << " regions:";
  unsigned sum = 0;
  for (Mapping const& m : regions) {
      sum += m.size();
      INFO() << "    [" << std::hex << m.start << " - " << m.end << "] "
             << (m.perm.readable ? "r" : "-")
             << (m.perm.writable ? "w" : "-")
             << (m.perm.exec ? "x" : "-")
             << " sz " << std::hex << m.size();
  }
  INFO() << "Totally in use: " << sum << " Bytes.";
}

static void detach_pid(int pid)
{
  int err = ptrace(PTRACE_DETACH, pid, 0, 0);
  if (err) {
    perror("ptrace detach");
  }
  INFO() << "Resumed PID " << pid;
}

std::shared_ptr<Elkvm::VM> attach_vm(int pid)
{
  INFO() << "Attaching to PID " << pid;
  stop_pid(pid);
  char *binaryname = NULL;
  binary_for_pid(pid, &binaryname);
  INFO() << "Binary name is: " << LOG_MAGENTA << binaryname << LOG_RESET;

  std::list<Mapping> regions;
  memory_map_for_pid(pid, regions);

  delete [] binaryname;
  detach_pid(pid);

  return nullptr;
}

int main(int argc, char **argv) {

  int opt;
  int err;
  int debug = 0;
  int gdb = 0;
  int myopts = 1;
  int attach_pid = -1;
  opterr = 0;

  while((opt = getopt(argc, argv, "+a:dD")) != -1) {
    switch(opt) {
      case 'd':
        debug = 1;
        myopts++;
        break;
      case 'D':
        gdb = 1;
        myopts++;
        break;
      case 'a':
        attach_pid = strtol(optarg, 0, 10);
        myopts++;
        break;
    }
  }

  std::shared_ptr<Elkvm::VM> vm = nullptr;

  if (attach_pid == -1) {
    // need additional binary and arguments
    if (optind >= argc) {
      print_usage(argv);
    }
    vm = run_new(argc, argv, myopts);
  } else {
    vm = attach_vm(attach_pid);
  }

  if (!vm) {
    ERROR() << "No VM created yet.";
    abort();
  }

  if(debug) {
    vm->set_debug(true);
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

