# Elf-loader
A low-level x86_64 Static ELF Loader. Features manual PT_LOAD segment mapping with ASLR for PIE binaries, custom stack initialization (argc/argv/envp), and Auxiliary Vector (auxv) setup for libc compatibility. Replaces execve by manually jumping to the entry point via inline assembly.

The loader handles the complex transition from a disk-based binary to a running process by implementing several kernel-level responsibilities. It supports Static PIE (Position Independent Executables) by generating a 48-bit random load base via getrandom, ensuring ASLR (Address Space Layout Randomization) compatibility. The core logic iterates through the ELF Program Headers, mapping PT_LOAD segments with precise page alignment and enforcing memory protections ($PROT\_READ, PROT\_WRITE, PROT\_EXEC$) via mprotect. Crucially, the loader manually constructs the Process Stack: it pushes environment variables and arguments onto a freshly allocated stack, followed by a carefully crafted Auxiliary Vector (auxv). This vector provides the target binary with essential metadata—such as the Program Header address (AT_PHDR) and random entropy (AT_RANDOM)—without which modern libc implementations would segfault. Execution is finally handed off using inline assembly to point %rsp to the new stack and jump to the calculated entry point.

Follow these steps to compile and run the loader using the provided `Makefile`:

### 1. Compile the Loader
To build the `elf-loader` binary, simply run:
```bash
make
./elf-loader ./hello_test
