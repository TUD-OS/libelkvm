#!/bin/sh

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

print_msg "/proc/sys/kernel/yama/ptrace_scope set to 0?"
val=`cat /proc/sys/kernel/yama/ptrace_scope`
test "x$val" = "x0"
return_check

run_test "ELKVM works?" 		001-run.exp
run_test "Proxy+debug works?" 	002-proxy.exp
