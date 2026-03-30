# elf-loader
A low-level x86_64 Static ELF Loader. Features manual PT_LOAD segment mapping with ASLR for PIE binaries, custom stack initialization (argc/argv/envp), and Auxiliary Vector (auxv) setup for libc compatibility. Replaces execve by manually jumping to the entry point via inline assembly.
