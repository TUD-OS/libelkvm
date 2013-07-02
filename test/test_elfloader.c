#include <check.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <sys/stat.h>
#include <unistd.h>

#include <elkvm.h>
#include <elfloader.h>

struct kvm_opts elfloader_test_kvm;
struct kvm_vm elfloader_test_vm;
const char *valid_binary_path = "./a.out";

void setup_elfloader() {
	kvm_init(&elfloader_test_kvm);
	kvm_vm_create(&elfloader_test_kvm, &elfloader_test_vm, VM_MODE_X86_64, 1, 0);
}

void teardown_elfloader() {
	kvm_vm_destroy(&elfloader_test_vm);
	kvm_cleanup(&elfloader_test_kvm);
}

START_TEST(test_elfloader_load_binary_uninitialized) {
	const char *empty_binary_path = "";
	elfloader_test_vm.pager.system_chunk.userspace_addr = 0;

	int err = elfloader_load_binary(&elfloader_test_vm, empty_binary_path);
	ck_assert_int_eq(err, -EIO);
}
END_TEST

START_TEST(test_elfloader_load_binary) {

	const char *empty_binary_path = "";
	int err = elfloader_load_binary(&elfloader_test_vm, empty_binary_path);
	ck_assert_int_ne(err, 0);

	const char *invalid_binary_path = "/tmp/23129uhuuukh.bin";
	err = elfloader_load_binary(&elfloader_test_vm, invalid_binary_path);
	printf("err no: %i msg: %s\n", err, strerror(-err));
	ck_assert_int_eq(err, -ENOENT);

	err = elfloader_load_binary(&elfloader_test_vm, valid_binary_path);
	ck_assert_int_eq(err, 0);

}
END_TEST

START_TEST(test_elfloader_load_program_header) {
	char *buf = malloc(32768);
	memset(buf, 'x', 32768);

	struct Elf_binary bin;
	bin.fd = open(valid_binary_path, O_RDONLY);
	if(bin.fd < 0) {
		ck_abort_msg("Could not open test binary");
	}

	bin.e = elf_begin(bin.fd, ELF_C_READ, NULL);
	/* get the first program header */
	GElf_Phdr phdr;
	gelf_getphdr(bin.e, 0, &phdr);

	/* load the first program header */
	int err =	elfloader_load_program_header(&elfloader_test_vm, &bin, phdr, buf);
	
	/* check if it has really been loaded into the buffer */
	for(int i = 0; i < phdr.p_memsz; i++) {
		ck_assert_int_ne(buf[i], 'x');
	}

	/* check if mappings have been created in the page tables */
	ck_abort_msg("Test not implemented!");

}
END_TEST

Suite *elfloader_suite() {
	Suite *s = suite_create("Elfloader");

	TCase *tc_loader = tcase_create("Loader");
	tcase_add_test(tc_loader, test_elfloader_load_binary);
	suite_add_tcase(s, tc_loader);

	return s;
}
