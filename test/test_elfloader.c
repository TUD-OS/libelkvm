#include <check.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include <elkvm.h>
#include <elfloader.h>

struct elkvm_opts elfloader_test_kvm;
struct kvm_vm elfloader_test_vm;
const char *valid_binary_path = "./a.out";

extern char **environ;
void setup_elfloader() {
	char *av = { "1234", "5678" };
	elkvm_init(&elfloader_test_kvm, 2, &av, environ);
	kvm_vm_create(&elfloader_test_kvm, &elfloader_test_vm, VM_MODE_X86_64, 1, 0, NULL);
}

void teardown_elfloader() {
	kvm_vm_destroy(&elfloader_test_vm);
	elkvm_cleanup(&elfloader_test_kvm);
}

START_TEST(test_elfloader_load_binary_uninitialized) {
	const char *empty_binary_path = "";
	elfloader_test_vm.pager.system_chunk.userspace_addr = 0;

	int err = elfloader_load_binary(&elfloader_test_vm, empty_binary_path);
	ck_assert_int_eq(err, -EIO);
}
END_TEST

START_TEST(test_elfloader_load_invalid_binary) {

	const char *empty_binary_path = "";
	int err = elfloader_load_binary(&elfloader_test_vm, empty_binary_path);
	ck_assert_int_ne(err, -EIO);

	const char *invalid_binary_path = "/tmp/23129uhuuukh.bin";
	err = elfloader_load_binary(&elfloader_test_vm, invalid_binary_path);
	ck_assert_int_eq(err, -ENOENT);
}
END_TEST

START_TEST(test_elfloader_load_valid_binary) {
	int err = elfloader_load_binary(&elfloader_test_vm, valid_binary_path);
	ck_assert_int_eq(err, 0);

	/*
	 * check for mappings in the page tables
	 */
	ck_abort_msg("Test for PT mappings not implemented");

}
END_TEST

START_TEST(test_elfloader_load_program_header) {
  struct elkvm_memory_region region;

	int err = posix_memalign(&region.host_base_p, 0x1000, 32768);
	ck_assert_int_eq(err, 0);
	memset(region.host_base_p, 'y', 32768);

	struct Elf_binary bin;
	bin.fd = open(valid_binary_path, O_RDONLY);
	if(bin.fd < 0) {
		ck_abort_msg("Could not open test binary");
	}

	if(elf_version(EV_CURRENT) == EV_NONE) {
		ck_abort_msg("Wrong ELF version");
	}

	bin.e = elf_begin(bin.fd, ELF_C_READ, NULL);
	ck_assert_ptr_ne(bin.e, NULL);

	/* get the first program header */
	GElf_Phdr phdr;
	gelf_getphdr(bin.e, 0, &phdr);

	/* load the first program header */
	err =	elfloader_load_program_header(&elfloader_test_vm, &bin, phdr, &region);
	ck_assert_int_eq(err, 0);

	/* check if it has really been loaded into the buffer */
	int off = phdr.p_vaddr & 0xFFF;
	for(int i = off; i < off + phdr.p_memsz; i++) {
    char *c = (char *)region.host_base_p + i;
		ck_assert_int_ne(c, 'y');
	}
}
END_TEST

Suite *elfloader_suite() {
	Suite *s = suite_create("Elfloader");

	TCase *tc_load_program_header = tcase_create("Load Program Header");
	tcase_add_test(tc_load_program_header, test_elfloader_load_program_header);
	suite_add_tcase(s, tc_load_program_header);

	TCase *tc_uninitialized_loader = tcase_create("Uninitialized Loader");
	tcase_add_test(tc_uninitialized_loader, test_elfloader_load_binary_uninitialized);
	suite_add_tcase(s, tc_uninitialized_loader);

	TCase *tc_loader = tcase_create("Initialized Loader");
	tcase_add_checked_fixture(tc_loader, setup_elfloader, teardown_elfloader);
	tcase_add_test(tc_loader, test_elfloader_load_invalid_binary);
	tcase_add_test(tc_loader, test_elfloader_load_valid_binary);
	suite_add_tcase(s, tc_loader);

	return s;
}
