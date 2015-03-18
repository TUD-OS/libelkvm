/* * libelkvm - A library that allows execution of an ELF binary inside a virtual
 * machine without a full-scale operating system
 * Copyright (C) 2013-2015 Florian Pester <fpester@os.inf.tu-dresden.de>, Björn
 * Döbel <doebel@os.inf.tu-dresden.de>,   economic rights: Technische Universitaet
 * Dresden (Germany)
 *
 * This file is part of libelkvm.
 *
 * libelkvm is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * libelkvm is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libelkvm.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>

#include <linux/unistd.h>

#include <stdio.h>
#include <stdlib.h>

enum {
#ifdef FAST_BENCH
	NUM_PID = 1,
	NUM_FSTAT = 1,
	NUM_MMAP = 1,
	NUM_EMPTY = 1,
#else
	NUM_PID   =  10000000,
	NUM_FSTAT =   1000000,
	NUM_EMPTY = 100000000,
	NUM_MMAP  =    100000,
#endif
	MMAP_SIZE =  4 * 1024 * 1024,
};


static void print_diff(char const *msg,
					   int iterations,
					   struct timeval* start,
					   struct timeval* stop)
{
	long long micro1 = start->tv_sec * 1000000 + start->tv_usec;
	long long micro2 = stop->tv_sec * 1000000 + stop->tv_usec;
	long long diff   = micro2 - micro1;

	printf("\033[32m%30s\033[0m %12lld us = %.4f us / iteration\n", msg,
		   diff, (float)diff / iterations);
}


#define TEST(name, iter, codeblock) \
	static void test_##name(void) { \
		struct timeval a, b; \
		int err = gettimeofday(&a, 0); \
		if (err) { \
			perror("gettimeofday"); \
			exit(err); \
		} \
		for (unsigned i = 0; i < (iter); ++i) { \
		codeblock; \
		} \
		err = gettimeofday(&b, 0); \
		if (err) { \
			perror("gettimeofday"); \
			exit(err); \
		} \
		print_diff(#name, iter, &a, &b); \
	}


TEST(empty, NUM_EMPTY, {});

TEST(getpid, NUM_PID,
	 {
		 long res = syscall(__NR_getpid);
		 (void)res;
	 }
	 );


TEST(fstat, NUM_FSTAT,
	 {
		 struct stat statbuf;
		 int fd = open("/proc/self/exe", O_RDONLY); // XXX /proc does not work...
		 if (fd < 0) {
			 perror("open");
		 }
		 int err = fstat(fd, &statbuf);
		 if (err) {
			 perror("fstat");
		 }
		 close(fd);
	 });


TEST(mmap, NUM_MMAP,
	 {
		 void *ptr = mmap(0, MMAP_SIZE, PROT_READ | PROT_WRITE,
						  MAP_ANONYMOUS | MAP_PRIVATE,
						  0, 0);
		 if (!ptr) {
			 perror("mmap");
			 exit(1);
		 }
		 munmap(ptr, MMAP_SIZE);
	 });


int main(int argc, char *argv[])
{
	test_empty();
	test_getpid();
	test_fstat();
	test_mmap();
	return 0;
}
