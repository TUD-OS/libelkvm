#!/bin/sh
#
# libelkvm - A library that allows execution of an ELF binary inside a virtual
# machine without a full-scale operating system
# Copyright (C) 2013-2015 Florian Pester <fpester@os.inf.tu-dresden.de>, Björn
# Döbel <doebel@os.inf.tu-dresden.de>,   economic rights: Technische Universitaet
# Dresden (Germany)
#
# This file is part of libelkvm.
#
# libelkvm is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# libelkvm is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with libelkvm.  If not, see <http://www.gnu.org/licenses/>.
#

export ELKVM_BUILD=../../build

# Print a banner message
print_msg () {
	printf "\033[35m%50s\033[0m " "$1"
}

# Call this after a test command to validate its result
return_check () {
	if [ $? -ne 0 ]; then
		echo "\033[31;1mFAILURE\033[0m"
		exit $?;
	fi
	echo "\033[32mOK\033[0m"
}

# Run expect test and check output
#
# Arguments:
#	$1 -- descriptive message
#   $2 -- name of expect script to run
run_test () {
	message=$1
	cmd=$2
	print_msg "$1"
	expect $2
	return_check
}

print_msg "expect installed?"
which expect >/dev/null
return_check

if [ -f /proc/sys/kernel/yama/ptrace_scope ]; then
	print_msg "/proc/sys/kernel/yama/ptrace_scope set to 0?"
	val=`cat /proc/sys/kernel/yama/ptrace_scope`
	test "x$val" = "x0"
	return_check
fi

run_test "ELKVM works?" 		001-run.exp
run_test "Proxy+debug works?" 	002-proxy.exp
run_test "Proxy+attach works?"  003-attach.exp
run_test "System calls work?"   004-syscalls.exp