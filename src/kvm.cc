#include <fcntl.h>
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cassert>
#include <cstring>

#include <elkvm/kvm.h>
#include <elkvm/vcpu.h>

namespace Elkvm {
namespace KVM {

VCPU::VCPU(int vmfd, unsigned num) {

    fd = ioctl(vmfd, KVM_CREATE_VCPU, num);
    assert(fd > 0 && "error creating vcpu");

    memset(&regs, 0, sizeof(struct kvm_regs));
    memset(&sregs, 0, sizeof(struct kvm_sregs));

    run_struct = reinterpret_cast<struct kvm_run *>(
        mmap(NULL, sizeof(struct kvm_run), PROT_READ | PROT_WRITE,
        MAP_SHARED, fd, 0));
    assert(run_struct != nullptr && "error allocating run_struct");
}

CURRENT_ABI::paramtype VCPU::get_reg(Elkvm::Reg_t reg) const {
  switch(reg) {
    case Elkvm::Reg_t::rax:
      return regs.rax;
    case Elkvm::Reg_t::rbx:
      return regs.rbx;
    case Elkvm::Reg_t::rcx:
      return regs.rcx;
    case Elkvm::Reg_t::rdx:
      return regs.rdx;
    case Elkvm::Reg_t::rsi:
      return regs.rsi;
    case Elkvm::Reg_t::rdi:
      return regs.rdi;
    case Elkvm::Reg_t::rsp:
      return regs.rsp;
    case Elkvm::Reg_t::rbp:
      return regs.rbp;
    case Elkvm::Reg_t::r8:
      return regs.r8;
    case Elkvm::Reg_t::r9:
      return regs.r9;
    case Elkvm::Reg_t::r10:
      return regs.r10;
    case Elkvm::Reg_t::r11:
      return regs.r11;
    case Elkvm::Reg_t::r12:
      return regs.r12;
    case Elkvm::Reg_t::r13:
      return regs.r13;
    case Elkvm::Reg_t::r14:
      return regs.r14;
    case Elkvm::Reg_t::r15:
      return regs.r15;
    case Elkvm::Reg_t::rip:
      return regs.rip;
    case Elkvm::Reg_t::rflags:
      return regs.rflags;
    case Elkvm::Reg_t::cr0:
      return sregs.cr0;
    case Elkvm::Reg_t::cr2:
      return sregs.cr2;
    case Elkvm::Reg_t::cr3:
      return sregs.cr3;
    case Elkvm::Reg_t::cr4:
      return sregs.cr4;
    case Elkvm::Reg_t::cr8:
      return sregs.cr8;
    case Elkvm::Reg_t::efer:
      return sregs.efer;
    case Elkvm::Reg_t::apic_base:
      return sregs.apic_base;

    default:
      assert(false);
      return -1;
  }
}

void VCPU::set_reg(Elkvm::Reg_t reg, CURRENT_ABI::paramtype val) {
  switch(reg) {
    case Elkvm::Reg_t::rax:
      regs.rax = val;
      break;
    case Elkvm::Reg_t::rbx:
      regs.rbx = val;
      break;
    case Elkvm::Reg_t::rcx:
      regs.rcx = val;
      break;
    case Elkvm::Reg_t::rdx:
      regs.rdx = val;
      break;
    case Elkvm::Reg_t::rsi:
      regs.rsi = val;
      break;
    case Elkvm::Reg_t::rdi:
      regs.rdi = val;
      break;
    case Elkvm::Reg_t::rsp:
      regs.rsp = val;
      break;
    case Elkvm::Reg_t::rbp:
      regs.rbp = val;
      break;
    case Elkvm::Reg_t::r8:
      regs.r8 = val;
      break;
    case Elkvm::Reg_t::r9:
      regs.r9 = val;
      break;
    case Elkvm::Reg_t::r10:
      regs.r10 = val;
      break;
    case Elkvm::Reg_t::r11:
      regs.r11 = val;
      break;
    case Elkvm::Reg_t::r12:
      regs.r12 = val;
      break;
    case Elkvm::Reg_t::r13:
      regs.r13 = val;
      break;
    case Elkvm::Reg_t::r14:
      regs.r14 = val;
      break;
    case Elkvm::Reg_t::r15:
      regs.r15 = val;
      break;
    case Elkvm::Reg_t::rip:
      regs.rip = val;
      break;
    case Elkvm::Reg_t::rflags:
      regs.rflags = val;
      break;
    case Elkvm::Reg_t::cr0:
      sregs.cr0 = val;
      break;
    case Elkvm::Reg_t::cr2:
      sregs.cr2 = val;
      break;
    case Elkvm::Reg_t::cr3:
      sregs.cr3 = val;
      break;
    case Elkvm::Reg_t::cr4:
      sregs.cr4 = val;
      break;
    case Elkvm::Reg_t::cr8:
      sregs.cr8 = val;
      break;
    case Elkvm::Reg_t::efer:
      sregs.efer = val;
      break;
    case Elkvm::Reg_t::apic_base:
      sregs.apic_base = val;
      break;

    default:
      assert(false);
  }
}

int VCPU::get_regs() {
  int err = ioctl(fd, KVM_GET_REGS, &regs);
  if(err) {
    return -errno;
  }

  return 0;
}

int VCPU::get_sregs() {
  int err = ioctl(fd, KVM_GET_SREGS, &sregs);
  if(err) {
    return -errno;
  }

  return 0;
}

int VCPU::set_regs() {
  int err = ioctl(fd, KVM_SET_REGS, &regs);
  if(err) {
    return -errno;
  }

  return 0;
}

int VCPU::set_sregs() {
  int err = ioctl(fd, KVM_SET_SREGS, &sregs);
  if(err) {
    return -errno;
  }

  return 0;
}

CURRENT_ABI::paramtype VCPU::get_interrupt_bitmap(unsigned idx) const {
  return sregs.interrupt_bitmap[idx];
}

CURRENT_ABI::paramtype VCPU::get_msr(uint32_t idx) {
  struct kvm_msrs *msr = reinterpret_cast<struct kvm_msrs *>(
      malloc(sizeof(struct kvm_msrs) + sizeof(struct kvm_msr_entry)));
  assert(msr != nullptr && "error allocating msr");

  msr->nmsrs = 1;
  msr->entries[0].index = idx;

  int err = ioctl(fd, KVM_GET_MSRS, msr);
  assert(err >= 0 && "error reading msrs");

  CURRENT_ABI::paramtype res = msr->entries[0].data;
  free(msr);
  return res;
}

void VCPU::set_msr(uint32_t idx, CURRENT_ABI::paramtype data) {
  struct kvm_msrs *msr = reinterpret_cast<struct kvm_msrs *>(
      malloc(sizeof(struct kvm_msrs) + sizeof(struct kvm_msr_entry)));
  assert(msr != nullptr && "error allocating msr");

  memset(msr, 0, sizeof(struct kvm_msrs) + sizeof(struct kvm_msr_entry));

  msr->nmsrs = 1;
  msr->entries[0].index = idx;
  msr->entries[0].data  = data;

  int err = ioctl(fd, KVM_SET_MSRS, msr);
  free(msr);
  assert(err >= 0 && "error setting msr");
}

Segment VCPU::get_reg(Elkvm::Seg_t segtype) const {
  switch(segtype) {
    case Elkvm::Seg_t::cs:
      return get_reg(&sregs.cs);
    case Elkvm::Seg_t::ds:
      return get_reg(&sregs.ds);
    case Elkvm::Seg_t::es:
      return get_reg(&sregs.es);
    case Elkvm::Seg_t::fs:
      return get_reg(&sregs.fs);
    case Elkvm::Seg_t::gs:
      return get_reg(&sregs.gs);
    case Elkvm::Seg_t::ss:
      return get_reg(&sregs.ss);
    case Elkvm::Seg_t::tr:
      return get_reg(&sregs.tr);
    case Elkvm::Seg_t::ldt:
      return get_reg(&sregs.ldt);
    case Elkvm::Seg_t::gdt:
      return get_reg(&sregs.gdt);
    case Elkvm::Seg_t::idt:
      return get_reg(&sregs.idt);
    default:
      assert(false);
  }
}

void VCPU::set_reg(Elkvm::Seg_t segtype, const Elkvm::Segment &seg) {
  switch(segtype) {
    case Elkvm::Seg_t::cs:
      set_reg(&sregs.cs, seg);
      break;
    case Elkvm::Seg_t::ds:
      set_reg(&sregs.ds, seg);
      break;
    case Elkvm::Seg_t::es:
      set_reg(&sregs.es, seg);
      break;
    case Elkvm::Seg_t::fs:
      set_reg(&sregs.fs, seg);
      break;
    case Elkvm::Seg_t::gs:
      set_reg(&sregs.gs, seg);
      break;
    case Elkvm::Seg_t::ss:
      set_reg(&sregs.ss, seg);
      break;
    case Elkvm::Seg_t::tr:
      set_reg(&sregs.tr, seg);
      break;
    case Elkvm::Seg_t::ldt:
      set_reg(&sregs.ldt, seg);
      break;
    case Elkvm::Seg_t::gdt:
      set_reg(&sregs.gdt, seg);
      break;
    case Elkvm::Seg_t::idt:
      set_reg(&sregs.idt, seg);
      break;
    default:
      assert(false);
  }
}

void VCPU::set_reg(struct kvm_dtable *ptr, const Elkvm::Segment &seg) {
  ptr->base = seg.get_base();
  ptr->limit = seg.get_limit();
}

void VCPU::set_reg(struct kvm_segment *ptr, const Elkvm::Segment &seg) {
  ptr->base = seg.get_base();
  ptr->limit = seg.get_limit();
  ptr->selector = seg.get_selector();
  ptr->type = seg.get_type();
  ptr->present = seg.is_present();
  ptr->dpl = seg.get_dpl();
  ptr->db = seg.get_db();
  ptr->s = seg.get_s();
  ptr->l = seg.get_l();
  ptr->g = seg.get_g();
  ptr->avl = seg.get_avl();
}

Segment VCPU::get_reg(const struct kvm_dtable * const ptr) const {
  return Elkvm::Segment(ptr->base, ptr->limit);
}

Segment VCPU::get_reg(const struct kvm_segment * const ptr) const {
  return Elkvm::Segment(ptr->selector,
            ptr->base,
            ptr->limit,
            ptr->type,
            ptr->present,
            ptr->dpl,
            ptr->db,
            ptr->s,
            ptr->l,
            ptr->g,
            ptr->avl);
}

int VCPU::run() {
  int err = ioctl(fd, KVM_RUN, 0);
  if(err != 0) {
    if(errno == EINTR) {
      fprintf(stderr, "VM interrupted by signal\n");
      return -EINTR;
    } else if(errno != EAGAIN) {
      fprintf(stderr, "ERROR running VCPU No: %i Msg: %s\n", errno, strerror(errno));
      return -1;
    }
  }

  return 0;
}

uint32_t VCPU::exit_reason() {
  return run_struct->exit_reason;
}

uint64_t VCPU::hardware_exit_reason() {
  return run_struct->hw.hardware_exit_reason;
}

uint64_t VCPU::hardware_entry_failure_reason() {
  return run_struct->fail_entry.hardware_entry_failure_reason;
}

std::ostream &VCPU::print_mmio(std::ostream &os) {
  os << "phys_addr: 0x" << std::hex << run_struct->mmio.phys_addr
     << " data[0]: " << run_struct->mmio.data[0]
     << " data[1]: " << run_struct->mmio.data[1]
     << " data[2]: " << run_struct->mmio.data[2]
     << " data[3]: " << run_struct->mmio.data[3]
     << " data[4]: " << run_struct->mmio.data[4]
     << " data[5]: " << run_struct->mmio.data[5]
     << " data[6]: " << run_struct->mmio.data[6]
     << " data[7]: " << run_struct->mmio.data[7]
     << " len: " << run_struct->mmio.len
     << " write: " << run_struct->mmio.is_write
     << std::endl;
  return os;
}

int init(struct elkvm_opts *opts) {

  opts->fd = open(KVM_DEV_PATH, O_RDWR);
  if(opts->fd < 0) {
    return -errno;
  }

  int version = ioctl(opts->fd, KVM_GET_API_VERSION, 0);
  if(version != KVM_EXPECT_VERSION) {
    return -ENOPROTOOPT;
  }

  opts->run_struct_size = ioctl(opts->fd, KVM_GET_VCPU_MMAP_SIZE, 0);
  if(opts->run_struct_size <= 0) {
    return -EIO;
  }

  return 0;
}

//namespace KVM
}
//namepace Elkvm
}
int elkvm_init(Elkvm::elkvm_opts *opts, int argc, char **argv, char **environ) {
  opts->argc = argc;
  opts->argv = argv;
  opts->environ = environ;

  return Elkvm::KVM::init(opts);
}

int elkvm_cleanup(Elkvm::elkvm_opts *opts) {
  close(opts->fd);
  opts->fd = 0;
  opts->run_struct_size = 0;
  return 0;
}


