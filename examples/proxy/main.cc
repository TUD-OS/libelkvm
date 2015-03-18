//
// libelkvm - A library that allows execution of an ELF binary inside a virtual
// machine without a full-scale operating system
// Copyright (C) 2013-2015 Florian Pester <fpester@os.inf.tu-dresden.de>, Björn
// Döbel <doebel@os.inf.tu-dresden.de>,   economic rights: Technische Universitaet
// Dresden (Germany)
//
// This file is part of libelkvm.
//
// libelkvm is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// libelkvm is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with libelkvm.  If not, see <http://www.gnu.org/licenses/>.
//

#include <fstream>
#include <iostream>
#include <cassert>
#include <cstring>

#include <elkvm/elkvm.h>
#include <elkvm/elkvm-log.h>
#include <elkvm/gdbstub.h>
#include <elkvm/gdt.h>
#include <elkvm/kvm.h>
#include <elkvm/vcpu.h>

#include <stdint.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
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

static void
initialize_elkvm(int argc, char**argv, char **env)
{
  int err = elkvm_init(&elkvm, argc, argv, env);
  if(err) {
    if(err == -ENOENT) {
      ERROR() << "/dev/kvm seems not to exist. Check your KVM installation!";
    }
    if(err == -EACCES) {
      ERROR() << "Access to /dev/kvm was denied. Check if you belong to the 'kvm' group!";
    }
    ERROR() << "ERROR initializing VM errno: " << -err << " Msg: "
            << strerror(-err);
    abort();
  }
}

std::shared_ptr<Elkvm::VM> run_new(int argc, char **argv, int myopts)
{
  char *binary = argv[myopts];
  char **binargv = &argv[myopts];
  int binargc = argc - myopts;

  initialize_elkvm(binargc, binargv, environ);

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

    size_t pages() const
    {
        unsigned sz = end - start;
        if (sz & ~(ELKVM_PAGESIZE-1)) { // need one more page if size is
                                    // not a multiple...
            sz += ELKVM_PAGESIZE;
        }
        return (sz / ELKVM_PAGESIZE);
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


static void
restore_to_pid(std::shared_ptr<Elkvm::VM> vm, int pid)
{
    (void)vm;
    (void)pid;
    // XXX: Need to update tracee state:
    //   1) Copy modified mem regions
    //      (INCLUDING NEW ALLOCATIONS!!)
    //   2) Set register state

    // TODO: IMPLEMENT ME
}


static void detach_pid(std::shared_ptr<Elkvm::VM> vm, int pid)
{
  if (vm != nullptr) {
    restore_to_pid(vm, pid);
  }

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
  initialize_elkvm(0, nullptr, nullptr);

  std::shared_ptr<Elkvm::VM> vm = elkvm_vm_create_raw(&elkvm);

  //vm->get_region_manager()->dump_regions();

  std::list<Mapping> regions;
  memory_map_for_pid(pid, regions);

  for (auto& reg : regions) {
      //INFO() << "size: " << reg.pages();
      std::shared_ptr<Elkvm::Region> r =
          vm->get_region_manager()->allocate_region(reg.size(), "ELVKM::attach");
      r->set_guest_addr(reg.start);

      ptopt_t pt_options = 0;
      if (reg.perm.writable) pt_options |= PT_OPT_WRITE;
      if (reg.perm.exec)     pt_options |= PT_OPT_EXEC;
      int err = vm->get_region_manager()->get_pager().map_region(r->base_address(),
                                                       r->guest_address(),
                                                       reg.pages(),
                                                       pt_options);
      assert(err == 0);
      void* ptr = vm->get_region_manager()->get_pager().get_host_p(r->guest_address());
      assert(ptr);
      //INFO() << "map_region(): " << err << " get_host_p(): " << ptr;
      {
          struct iovec local, remote;
          local.iov_base = r->base_address();
          local.iov_len  = reg.size();
          remote.iov_base = reinterpret_cast<void*>(r->guest_address());
          remote.iov_len = reg.size();
          ssize_t bytes = process_vm_readv(pid,
                                           &local, 1,
                                           &remote, 1,
                                           0);
          //INFO() << "Read " << bytes << " bytes from remote process.";
          if (bytes == -1) {
              INFO() << "Error reading region [" << std::hex << r->guest_address()
                     << " - " << (r->guest_address() + reg.size()) << "]";
              INFO() << "Error message: " << strerror(errno);
          }
      }
  }

  vm->get_region_manager()->dump_regions();

  struct user_regs_struct user_regs;
  int err = ptrace(PTRACE_GETREGS, pid, 0, &user_regs);
  if (err) {
    perror("ptrace getregs");
    abort();
  }
  const auto& cpu = vm->get_vcpu(0);
  cpu->set_reg(Elkvm::rax, user_regs.rax);
  cpu->set_reg(Elkvm::rbx, user_regs.rbx);
  cpu->set_reg(Elkvm::rcx, user_regs.rcx);
  cpu->set_reg(Elkvm::rdx, user_regs.rdx);
  cpu->set_reg(Elkvm::r8, user_regs.r8);
  cpu->set_reg(Elkvm::r9, user_regs.r9);
  cpu->set_reg(Elkvm::r10, user_regs.r10);
  cpu->set_reg(Elkvm::r11, user_regs.r11);
  cpu->set_reg(Elkvm::r12, user_regs.r12);
  cpu->set_reg(Elkvm::r13, user_regs.r13);
  cpu->set_reg(Elkvm::r14, user_regs.r14);
  cpu->set_reg(Elkvm::r15, user_regs.r15);

  cpu->set_reg(Elkvm::rip, user_regs.rip);
  cpu->set_reg(Elkvm::rsp, user_regs.rsp);
  cpu->set_reg(Elkvm::rbp, user_regs.rbp);
  cpu->set_reg(Elkvm::rsi, user_regs.rsi);
  cpu->set_reg(Elkvm::rdi, user_regs.rdi);
  cpu->set_reg(Elkvm::rflags, user_regs.eflags);

#if 0
  auto gdt_region = vm->get_gdt_region();
  elkvm_gdt_segment_descriptor entry;
  elkvm_gdt_create_segment_descriptor(&entry, user_regs.fs_base, 0xFFFFFFFF,
            GDT_SEGMENT_PRESENT | GDT_SEGMENT_WRITEABLE | GDT_SEGMENT_BIT |
            GDT_SEGMENT_PRIVILEDGE_USER, GDT_SEGMENT_PAGE_GRANULARITY | GDT_SEGMENT_LONG);
#endif
  Elkvm::Segment fs = cpu->get_reg(Elkvm::Seg_t::fs);
  fs.set_base(user_regs.fs_base);
  fs.set_selector(0x28);
  cpu->set_reg(Elkvm::fs, fs);

  cpu->set_sregs();
  cpu->set_regs();

  print(std::cout, *cpu);

  //detach_pid(pid);
  //elkvm_cleanup(&elkvm);
  return vm;
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

  if (!vm or (vm == nullptr)) {
    ERROR() << "No VM created yet.";
    abort();
  }

  if(debug) {
    vm->set_debug(true);
  }

  if(gdb) {
    //gdbstub will take it from here!
    Elkvm::Debug::gdb_session gdb(*vm);
    return 0;
  }

  err = vm->run();
  if(err) {
    printf("ERROR running VCPU errno: %i Msg: %s\n", -err, strerror(-err));
    return -1;
  }

  if (attach_pid != -1) {
    INFO() << "Detaching from PID " << std::dec << attach_pid;
    detach_pid(vm, attach_pid);
  }

  err = elkvm_cleanup(&elkvm);
  if(err) {
    printf("ERROR cleaning up errno: %i Msg: %s\n", -err, strerror(-err));
    return -1;
  }

  printf("DONE\n");
  return 0;
}

