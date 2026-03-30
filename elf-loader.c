// SPDX-License-Identifier: BSD-3-Clause

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <elf.h>
#include <sys/resource.h>
#include <stdbool.h>
#include <sys/syscall.h>
#include <stdint.h>

#define AUXV_ENTR(ENTRY, VALUE) \
do {	\
	stack_addr_top -= sizeof(long); \
	*((long *)stack_addr_top) = VALUE; \
	stack_addr_top -= sizeof(long); \
	*((long *)stack_addr_top) = ENTRY; \
} while (0)

#define PLATFORM "x86_64"

void *map_elf(const char *filename)
{
	// This part helps you store the content of the ELF file inside the buffer.
	struct stat st;
	void *file;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	fstat(fd, &st);

	file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED) {
		perror("mmap");
		close(fd);
		exit(1);
	}

	return file;
}
/*
 * Short understanding @ Assignment2:
 * DID: ELF Header Validation
 * Validate ELF magic bytes - "Not a valid ELF file" + exit code 3 if invalid.
 * Validate ELF class is 64-bit (ELFCLASS64) - "Not a 64-bit ELF" + exit code 4 if invalid.
 * DID: Load PT_LOAD segments
 * For minimal syscall-only binaries.
 * For each PT_LOAD segment:
 * Map the segments in memory. Permissions can be RWX for now.
 * Set memory permissions according to program header p_flags (PF_R, PF_W, PF_X).
 * Use mprotect() or map with the correct permissions directly using mmap()
 * DID: Support Static Non-PIE Binaries with libc
 * Must set up a valid process stack, including:
 * argc, argv, envp
 * auxv vector (with entries like AT_PHDR, AT_PHENT, AT_PHNUM, etc.)
 * Note: Beware of the AT_RANDOM, AT_PHDR entries, the application will crash if you do not set them up properly.
 * DID: Support Static PIE Executables
 * Map PT_LOAD segments at a random load base.
 * Adjust virtual addresses of segments and entry point by load_base.
 * Stack setup (argc, argv, envp, auxv) same as above.
 */

void load_and_run(const char *filename, int argc, char **argv, char **envp)
{
	// Contents of the ELF file are in the buffer: elf_contents[x] is the x-th byte of the ELF file.
	void *elf_contents = map_elf(filename);
	Elf64_Ehdr *header = (Elf64_Ehdr *)elf_contents;

	if (strncmp(header->e_ident, ELFMAG, 4)) {
		perror("Not a valid ELF file\n");
		exit(3);
	}
	if (header->e_ident[EI_CLASS] != ELFCLASS64) {
		perror("Not a 64-bit ELF\n");
		exit(4);
	}
	uint8_t random[16];

	syscall(SYS_getrandom, random, 8, 0);
	long page_size = sysconf(_SC_PAGESIZE);
	//Limit to userspace not kernel spacwe
	uintptr_t random_base = (*(uint64_t *)random) & 0x00007FFFFFFFF000;

	random_base = random_base & ~(page_size - 1);
	size_t phdr_addr = 0;
	bool first_pt_load = false;

	for (size_t i = 0; i < header->e_phnum; ++i) {
		Elf64_Phdr *curr = (Elf64_Phdr *)(elf_contents + header->e_phoff + i * header->e_phentsize);

		if (curr->p_type == PT_LOAD) {
			if (curr->p_offset == 0 && !first_pt_load) {
				first_pt_load = true;
				phdr_addr = curr->p_vaddr + header->e_phoff + ((header->e_type == ET_DYN) ? random_base : 0);
			}
			uint8_t *aligned_addr = (uint8_t *)((curr->p_vaddr + ((header->e_type == ET_DYN) ? random_base : 0)) & ~(curr->p_align - 1));
			size_t offset = (curr->p_vaddr + ((header->e_type == ET_DYN) ? random_base : 0)) - (size_t)aligned_addr;
			size_t map_size = offset + curr->p_memsz;

			void *addr = mmap(aligned_addr, map_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

			memcpy(addr + offset, ((uint8_t *)elf_contents + curr->p_offset), curr->p_filesz);
			if (curr->p_memsz > curr->p_filesz)
				memset(((uint8_t *)addr + offset + curr->p_filesz), 0, (curr->p_memsz - curr->p_filesz));
			size_t permissions = 0;

			if (curr->p_flags & PF_X)
				permissions |= PROT_EXEC;
			if (curr->p_flags & PF_W)
				permissions |= PROT_WRITE;
			if (curr->p_flags & PF_R)
				permissions |= PROT_READ;
			mprotect(addr, map_size, permissions);
		}
	}
	struct rlimit stack_result;
	//soft limit field is enforce by the kernel
	//hard limit filed: the max value the soft can be raised to. (only root)
	long stack_size = getrlimit(RLIMIT_STACK, &stack_result);
	uint8_t *stack_addr_base = mmap(NULL, (uint64_t)stack_result.rlim_cur, PROT_READ | PROT_WRITE | PROT_EXEC,  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	uint8_t *stack_addr_top = (uint8_t *)(stack_addr_base) +  (uint64_t)stack_result.rlim_cur;
	int envp_count = 0;
	uint8_t **addresses = calloc(1000, sizeof(uint8_t *));
	uint8_t **addresses2 = calloc(1000, sizeof(uint8_t *));

	for (; envp[envp_count] != NULL; envp_count++) {
		size_t len = strlen(envp[envp_count]) + 1;

		stack_addr_top -= len;
		memcpy(stack_addr_top, envp[envp_count], len);
		if (envp_count < 1000)
			addresses[envp_count] = (uint8_t *)stack_addr_top;
	}
	for (int i = 0; i < argc; ++i) {
		size_t len = strlen(argv[i]) + 1;

		stack_addr_top -= len;
		memcpy(stack_addr_top, argv[i], len);
		addresses[i + envp_count] = (uint8_t *)stack_addr_top;
	}
	int auxv_count = 0;
	size_t plat_len = strlen((char *)PLATFORM) + 1;

	stack_addr_top -= plat_len;
	memcpy(stack_addr_top, PLATFORM, plat_len);
	addresses2[0] = (uint8_t *)stack_addr_top;
	auxv_count++;
	syscall(SYS_getrandom, random, 16, 0);
	stack_addr_top -= 16;
	memcpy(stack_addr_top, random, 16);
	addresses2[1] = (uint8_t *)stack_addr_top;
	auxv_count++;
	stack_addr_top = (uint8_t *)((uintptr_t)stack_addr_top & ~0xF);
	AUXV_ENTR(AT_NULL, 0);
	AUXV_ENTR(AT_PLATFORM, (long)addresses2[0]);
	AUXV_ENTR(AT_RANDOM, (long)(addresses2[1]));
	AUXV_ENTR(AT_PAGESZ, page_size);
	AUXV_ENTR(AT_PHENT, header->e_phentsize);
	AUXV_ENTR(AT_PHNUM, header->e_phnum);
	AUXV_ENTR(AT_PHDR, phdr_addr);
	stack_addr_top -= sizeof(void *);
	*((uint8_t **)stack_addr_top) = NULL;
	for (int i = envp_count - 1; i >= 0; --i) {
		stack_addr_top -= sizeof(void *);
		*((uint8_t **)stack_addr_top) = addresses[i];
	}
	stack_addr_top -= sizeof(void *);
	*((uint8_t **)stack_addr_top) = NULL;
	for (int i = argc - 1; i >= 0; --i) {
		stack_addr_top -= sizeof(void *);
		*((uint8_t **)stack_addr_top) = addresses[i + envp_count];
	}
	stack_addr_top -= sizeof(long);
	*((long *)stack_addr_top) = argc;
	free(addresses);
	free(addresses2);
	void *sp = stack_addr_top;
	void (*entry)() = (void(*)())(header->e_entry + ((header->e_type == ET_DYN) ? random_base : 0));

	__asm__ __volatile__(
			"mov %0, %%rsp\n"
			"xor %%rbp, %%rbp\n"
			"jmp *%1\n"
			:
			: "r"(sp), "r"(entry)
			: "memory"
			);
}

int main(int argc, char **argv, char **envp)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <static-elf-binary>\n", argv[0]);
		exit(1);
	}

	load_and_run(argv[1], argc - 1, &argv[1], envp);
	return 0;
}
