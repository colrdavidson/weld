#include "minilib.c"

#define panic(...) do { dprintf(2, __VA_ARGS__); exit(1); } while (0)
#define floor_size(addr, size) ((addr) - ((addr) % (size)))
#define round_size(addr, size) (((addr) + (size)) - ((addr) % (size)))

#define ELFCLASS64  2
#define ELFDATA2LSB 1
#define EM_X86_64   62

#define SHF_WRITE 0x1
#define SHF_ALLOC 0x2

#define PT_LOAD 1

enum {
	SHT_NULL = 0,
	SHT_PROGBITS,
	SHT_SYMTAB,
	SHT_STRTAB,
	SHT_RELA,
	SHT_HASH,
	SHT_DYNAMIC
};

#pragma pack(1)
typedef struct {
	u8 magic[4];
	u8 class;
	u8 endian;
	u8 hdr_version;
	u8 target_abi;
	u8 pad[8];
} ELF_Pre_Header;

typedef struct {
	u8  ident[16];
	u16 type;
	u16 machine;
	u32 version;
	u64 entrypoint;
	u64 program_hdr_offset;
	u64 section_hdr_offset;
	u32 flags;
	u16 eh_size;
	u16 program_hdr_entry_size;
	u16 program_hdr_num;
	u16 section_hdr_entry_size;
	u16 section_hdr_num;
	u16 section_hdr_str_idx;
} ELF64_Header;

typedef struct {
	u32 type;
	u32 flags;
	u64 offset;
	u64 virtual_addr;
	u64 physical_addr;
	u64 file_size;
	u64 mem_size;
	u64 align;
} ELF64_Program_Header;

typedef struct {
	u32 name;
	u32 type;
	u64 flags;
	u64 addr;
	u64 offset;
	u64 size;
	u32 link;
	u32 info;
	u64 addr_align;
	u64 entry_size;
} ELF64_Section_Header;
#pragma pack()

typedef struct {
	u32 type;
	u64 offset;
	u64 addr;
	u64 size;
} Segment;

typedef struct {
	u8 *data;
	u64 size;
} Slice;

Slice to_slice(u8 *data, u64 size) {
	Slice s;
	s.data = data;
	s.size = size;
	return s;
}

Slice slice_idx(Slice s, u64 idx) {
	if (idx > s.size) {
		panic("Invalid idx %d:%d!\n", idx, s.size);
	}

	Slice out;
	out.data = s.data + idx;
	out.size = s.size - idx;
	return out;
}

Slice load_file(char *filename) {
	int fd = open(filename, O_RDONLY);
	if (fd < 0) {
		panic("Failed to open %s\n", filename);
	}

	u64 length = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);

	u8 *data = (u8 *)malloc(length + 1);
	read(fd, data, length);
	close(fd);

	return to_slice(data, length);
}

void hexdump(Slice s) {
	int display_width = 32;

	printf("[");
	int tail = s.size % display_width;
	int trunc_width = s.size - tail;
	for (size_t i = 0; i < trunc_width; i += display_width) {
		int j = 0;
		for (; j < (display_width - 2); j += 2) {
			printf("%02x%02x ", s.data[i+j], s.data[i+j+1]);
		}

		if (i + display_width == s.size) {
			printf("%02x%02x ", s.data[i+j], s.data[i+j+1]);
		} else {
			printf("%02x%02x\n", s.data[i+j], s.data[i+j+1]);
		}
	}

	if (tail) {
		int j = trunc_width;
		for (; j < (s.size - 2); j += 2) {
			printf("%02x%02x ", s.data[j], s.data[j+1]);
		}

		int rem = s.size - j;
		if (rem == 2) {
			printf("%02x%02x", s.data[j], s.data[j+1]);
		} else if (rem == 1) {
			printf("%02x", s.data[j]);
		}
	}
	printf("]\n");
}


/*```

	A quick ELF briefer:

	----------------------------------
    | ELF Header                     |--+
    ----------------------------------  |
    | Program Header                 |  |
    ----------------------------------  |
 +->| Sections: .text, .strtab, etc. |  |
 |  ----------------------------------  |
 +--| Section Headers                |<-+
    ----------------------------------

	Finding the Section Header table: ("What sections does this ELF have?")
	File start + ELF_Header.shoff -> Section_Header table

	Finding the String Table for Section Header Names: ("How do I know what section 1 is called?")
	Section_Header table[ELF_Header.shstrndx] -> Section Header for Name Table

	Finding Data for Section Headers: ("How do I get the data in the .text section?")
	File start + Section_Header.offset -> Section Data

```*/
u64 load_elf(Slice s) {
	if (s.size < sizeof(ELF64_Header)) {
		panic("Invalid elf file!\n");
	}

	// Checking a small chunk of the ELF header (Calling it a Pre_Header here)
	// to know how to interpret the rest of the header
	// The full header could be ELF32 or ELF64 or garbage,
	// I won't know until I've scanned the Pre_Header fields
	u8 magic[4] = { 0x7F, 'E', 'L', 'F' };
	ELF_Pre_Header *pre_hdr = (ELF_Pre_Header *)s.data;
	if (!memeq(pre_hdr->magic, magic, sizeof(magic))) {
		panic("File is not an ELF!\n");
	}
	if (pre_hdr->class != ELFCLASS64 || pre_hdr->endian != ELFDATA2LSB) {
		panic("TODO: Only supports 64 bit, little endian ELF\n");
	}

	ELF64_Header *elf_hdr = (ELF64_Header *)s.data;
	if (elf_hdr->machine != EM_X86_64) {
		panic("TODO: Only supports x86_64\n");
	}
	if (elf_hdr->version != 1) {
		panic("Invalid ELF version\n");
	}


	// Ensure that the ELF file actually has enough space to fit the full claimed program header table
	if (elf_hdr->program_hdr_offset + (elf_hdr->program_hdr_num * sizeof(ELF64_Program_Header)) > s.size) {
		panic("Invalid elf file!\n");
	}
	ELF64_Program_Header *program_hdr_table = (ELF64_Program_Header *)(s.data + elf_hdr->program_hdr_offset);

	// Load segments into memory
	for (int i = 0; i < elf_hdr->program_hdr_num; i += 1) {
		ELF64_Program_Header *p_hdr = &program_hdr_table[i];


		if (p_hdr->type != PT_LOAD) {
			continue;
		}

		bool exec_perm  = (p_hdr->flags & 0x1) == 0x1;
		bool write_perm = (p_hdr->flags & 0x2) == 0x2;
		bool read_perm  = (p_hdr->flags & 0x4) == 0x4;

		printf("0x%02x | %s%s%s | vaddr: 0x%08x paddr: 0x%08x memsz: 0x%08x | align: %d\n",
			i, (exec_perm) ? "X" : " ", (write_perm) ? "W" : " ", (read_perm) ? "R" : " ",
			p_hdr->virtual_addr, p_hdr->physical_addr, p_hdr->mem_size, p_hdr->align);

		u64 aligned_addr = floor_size(p_hdr->virtual_addr, p_hdr->align);
		u64 region_size  = round_size(p_hdr->mem_size, p_hdr->align);

		u8 *seg = mmap((void *)aligned_addr, region_size, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 0, 0);
		if ((u64)seg != aligned_addr) {
			panic("WTF? 0x%08x != 0x%08x\n", seg, aligned_addr);
		}

		u8 *segment_ptr = s.data + p_hdr->offset;
		memcpy(seg, segment_ptr, p_hdr->file_size);
	}

	// Ensure that the ELF file actually has enough space to fit the full claimed section header table
	if (elf_hdr->section_hdr_offset + (elf_hdr->section_hdr_num * sizeof(ELF64_Section_Header)) > s.size) {
		panic("Invalid elf file!\n");
	}
	ELF64_Section_Header *section_hdr_table = (ELF64_Section_Header *)(s.data + elf_hdr->section_hdr_offset);

	// Get section header name table header
	if (elf_hdr->section_hdr_str_idx >= elf_hdr->section_hdr_num) {
		panic("Invalid section header name table index\n");
	}
	ELF64_Section_Header *section_strtable_hdr = &section_hdr_table[elf_hdr->section_hdr_str_idx];
	if (section_strtable_hdr->type != SHT_STRTAB) {
		panic("Section header name table is invalid\n");
	}

	// Get section header name table
	if ((section_strtable_hdr->offset + section_strtable_hdr->size) > s.size) {
		panic("Section header name table is too large for file?\n");
	}
	Slice strtable = to_slice(s.data + section_strtable_hdr->offset, section_strtable_hdr->size);

	for (int i = 0; i < elf_hdr->section_hdr_num; i += 1) {
		ELF64_Section_Header *s_hdr = &section_hdr_table[i];
		Slice sect_name = slice_idx(strtable, s_hdr->name);

		printf("%d | %s\n", i, (char *)sect_name.data);
		if (s_hdr->type == SHT_PROGBITS || s_hdr->type == SHT_STRTAB) {
			Slice sect = slice_idx(s, s_hdr->offset);
			//hexdump(sect);
		}
	}

	return elf_hdr->entrypoint;
}

int main(int argc, char **argv) {
	if (argc < 2) {
		panic("Please provide the linker a program to link\n");
	}

	Slice s = load_file(argv[1]);
	printf("Loaded %s and got %d B\n", argv[1], s.size);
	u64 entrypoint = load_elf(s);

/*
	typedef void (*extern_main)(int argc, char **argv);
	((extern_main)(entrypoint))(argc - 1, argv + 1);
*/

	return 0;
}
