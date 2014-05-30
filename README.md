# Install

You need to install the following additional packages in your distribution:
* check
* cmake
* libudis86

ELKVM uses cmake as a build system, you can build it in any directory you like to.
In that directory you need to run the following:

cmake PATH_TO_ELKVM_TOPLEVEL_DIRECTORY
make
make install
ldconfig

This will build the ELKVM library and an example application that just redirects all
system calls to the host Linux kernel. You can find the source code for this
application in the examples/ directory.

You also need to add the following patch to your Linux kernel for ELKVM to work:

diff --git a/arch/x86/kvm/vmx.c b/arch/x86/kvm/vmx.c
index 064d0be..501e6a9 100644
--- a/arch/x86/kvm/vmx.c
+++ b/arch/x86/kvm/vmx.c
@@ -5118,9 +5118,10 @@ static int handle_halt(struct kvm_vcpu *vcpu)
 
 static int handle_vmcall(struct kvm_vcpu *vcpu)
 {
-       skip_emulated_instruction(vcpu);
-       kvm_emulate_hypercall(vcpu);
-       return 1;
+//     skip_emulated_instruction(vcpu);
+//     kvm_emulate_hypercall(vcpu);
+  vcpu->run->exit_reason = KVM_EXIT_HYPERCALL;
+       return 0;
 }

# Building and Running the Tests

ELKVM uses gmock and gtest for unit testing. By default tests are not built. If you
want to build and run the tests you have to enable

libelkvm_build_tests

which you can do for example by running

ccmake PATH_TO_ELKVM_TOPLEVEL_DIRECTORY

inside your build directory. Additionally you have to have the gmock sources in
test/include/gmock. You can get those from https://code.google.com/p/googlemock/


Happy Hacking! :)
