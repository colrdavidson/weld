#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#include "minilib.c"

#define panic(...) do { dprintf(2, __VA_ARGS__); exit(1); } while (0)

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
	u64 entry;
	u64 program_hdr_offset;
	u64 section_hdr_offset;
	u32 flags;
	u16 ehsize;
	u16 program_hdr_entry_size;
	u16 program_hdr_num;
	u16 section_hdr_num;
	u16 section_hdr_str_idx;
} ELF64_Header;

typedef struct {
	uint8_t *data;
	u64 size;
} Slice;

Slice load_file(char *filename) {
	int fd = open(filename, O_RDONLY);
	if (fd < 0) {
		panic("Failed to open %s\n", filename);
	}

	u64 length = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);

	uint8_t *data = (uint8_t *)malloc(length + 1);
	read(fd, data, length);
	close(fd);

	Slice f;
	f.data = data;
	f.size = length;
	return f;
}

void print_hexdump(Slice s) {
	int display_width = 16;

	printf("[");
	int tail = s.size % display_width;
	int trunc_width = s.size - tail;
	for (size_t i = 0; i < trunc_width; i += display_width) {
		int j = 0;
		for (; j < (display_width - 2); j += 2) {
			printf("%02x%02x ", s.data[i+j], s.data[i+j+1]);
		}

		if (i + display_width == s.size) {
			printf("%02x%02x", s.data[i+j], s.data[i+j+1]);
		} else {
			printf("%02x%02x\n", s.data[i+j], s.data[i+j+1]);
		}
	}

	if (tail) {
		int j = trunc_width;
		for (; j < (s.size - 2); j += 2) {
			printf("%02x%02x ", s.data[j], s.data[j+1]);
		}
		printf("%02x%02x", s.data[j], s.data[j+1]);
	}
	printf("]\n");
}

int main(int argc, char **argv) {
	if (argc < 2) {
		panic("Please provide the linker a program to link\n");
	}

	Slice s = load_file(argv[1]);
	printf("Loaded %s and got %d B\n", argv[1], s.size);
	//print_hexdump(s);
	//parse_elf(s);

	return 0;
}
