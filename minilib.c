#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/syscall.h>
#include <sys/types.h>

#pragma once

typedef unsigned long long u64;
typedef uint32_t           u32;
typedef uint16_t           u16;
typedef uint8_t             u8;

typedef long long          i64;
typedef int32_t            i32;
typedef int16_t            i16;
typedef int8_t              i8;

static __inline long __syscall0(long n)
{
	unsigned long ret;
	__asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n) : "rcx", "r11", "memory");
	return ret;
}

static __inline long __syscall1(long n, long a1)
{
	unsigned long ret;
	__asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
	return ret;
}

static __inline long __syscall2(long n, long a1, long a2)
{
	unsigned long ret;
	__asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2)
						  : "rcx", "r11", "memory");
	return ret;
}

static __inline long __syscall3(long n, long a1, long a2, long a3)
{
	unsigned long ret;
	__asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
						  "d"(a3) : "rcx", "r11", "memory");
	return ret;
}

static __inline long __syscall4(long n, long a1, long a2, long a3, long a4)
{
	unsigned long ret;
	register long r10 __asm__("r10") = a4;
	__asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
						  "d"(a3), "r"(r10): "rcx", "r11", "memory");
	return ret;
}

static __inline long __syscall5(long n, long a1, long a2, long a3, long a4, long a5)
{
	unsigned long ret;
	register long r10 __asm__("r10") = a4;
	register long r8 __asm__("r8") = a5;
	__asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
						  "d"(a3), "r"(r10), "r"(r8) : "rcx", "r11", "memory");
	return ret;
}

static __inline long __syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
	unsigned long ret;
	register long r10 __asm__("r10") = a4;
	register long r8 __asm__("r8") = a5;
	register long r9 __asm__("r9") = a6;
	__asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
						  "d"(a3), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
	return ret;
}

#define __scc(X) ((long) (X))
#define __syscall1(n,a) __syscall1(n,__scc(a))
#define __syscall2(n,a,b) __syscall2(n,__scc(a),__scc(b))
#define __syscall3(n,a,b,c) __syscall3(n,__scc(a),__scc(b),__scc(c))
#define __syscall4(n,a,b,c,d) __syscall4(n,__scc(a),__scc(b),__scc(c),__scc(d))
#define __syscall5(n,a,b,c,d,e) __syscall5(n,__scc(a),__scc(b),__scc(c),__scc(d),__scc(e))
#define __syscall6(n,a,b,c,d,e,f) __syscall6(n,__scc(a),__scc(b),__scc(c),__scc(d),__scc(e),__scc(f))
#define __syscall7(n,a,b,c,d,e,f,g) (__syscall)(n,__scc(a),__scc(b),__scc(c),__scc(d),__scc(e),__scc(f),__scc(g))

#define __SYSCALL_NARGS_X(a,b,c,d,e,f,g,h,n,...) n
#define __SYSCALL_NARGS(...) __SYSCALL_NARGS_X(__VA_ARGS__,7,6,5,4,3,2,1,0,)
#define __SYSCALL_CONCAT_X(a,b) a##b
#define __SYSCALL_CONCAT(a,b) __SYSCALL_CONCAT_X(a,b)
#define __SYSCALL_DISP(b,...) __SYSCALL_CONCAT(b,__SYSCALL_NARGS(__VA_ARGS__))(__VA_ARGS__)

#define __syscall(...) __SYSCALL_DISP(__syscall,__VA_ARGS__)
#define syscall(...) __syscall_ret(__syscall(__VA_ARGS__))

#define PROT_READ  1
#define PROT_WRITE 2
#define PROT_EXEC  4
#define MAP_PRIVATE   0x02
#define MAP_FIXED     0x10
#define MAP_ANONYMOUS 0x20
#define O_RDONLY 0
#define SEEK_SET 0
#define SEEK_END 2

static long errno = 0;

i64 __syscall_ret(u64 r) {
	if (r > -4096UL) {
		errno = -r;
		return -1;
	}
	return r;
}

ssize_t write(int fd, uint8_t *buf, u64 size) {
	int ret = syscall(SYS_write, fd, buf, size);
	if (ret != size) {
		return -1;
	}
	return ret;
}

void exit(int code) {
	syscall(SYS_exit, code);
	for (;;) { }
}

int open(char *pathname, int flags) {
	return syscall(SYS_open, pathname, flags);
}

int close(int fd) {
	return syscall(SYS_close, fd);
}

i64 lseek(int fd, i64 offset, u32 flag) {
	return syscall(SYS_lseek, fd, offset, flag);
}

i64 read(int fd, uint8_t *buf, u64 size) {
	return syscall(SYS_read, fd, buf, size);
}

void *mmap(void *start, size_t len, int prot, int flags, int fd, i64 off) {
	return (void *)syscall(SYS_mmap, start, len, prot, flags, fd, off);
}

void *malloc(size_t size) {
	int len = size + sizeof(size);
	int *ptr_len = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

	*ptr_len = len;
	return (void *)(ptr_len + 1);
}

int itoa(uint64_t i, uint8_t base, uint8_t *buf) {
    static const char bchars[] = "0123456789ABCDEF";

    int      pos   = 0;
    int      o_pos = 0;
    int      top   = 0;
    uint8_t tbuf[64];

    if (i == 0 || base > 16) {
        buf[0] = '0';
        buf[1] = '\0';
        return 2;
    }

    while (i != 0) {
        tbuf[pos] = bchars[i % base];
        pos++;
        i /= base;
    }
    top = pos--;

    for (o_pos = 0; o_pos < top; pos--, o_pos++) {
        buf[o_pos] = tbuf[pos];
    }

    buf[o_pos] = 0;
    return o_pos + 1;
}

int putc(int fd, char c) {
	return write(fd, (uint8_t *)&c, 1);
}

void print(int fd, char *c) {
	uint8_t obuf[128];

	int i = 0;
	for (; *c != 0; i++) {
		if (i > 64) {
			write(fd, obuf, i);
			i = 0;
		}

		obuf[i] = *c;
		c++;
	}

	if (i > 0) {
		write(fd, obuf, i);
	}
}

void putn(int fd, u64 i, u8 base) {
	uint8_t tbuf[64];

	if (base > 16) return;

	int size = itoa(i, base, tbuf);
	write(fd, tbuf, size - 1);
}

void dprintf(int fd, char *fmt, ...) {
	__builtin_va_list args;
	__builtin_va_start(args, fmt);

	u32 min_len = 0;
	for (char *c = fmt; *c != 0; c++) {
		if (*c != '%') {
			uint8_t obuf[128];

			int i = 0;
			for (; *c != 0 && *c != '%'; i++) {
				if (i > 128) {
					write(fd, obuf, i);
					i = 0;
				}

				obuf[i] = *c;
				c++;
			}

			if (i > 0) {
				write(fd, obuf, i);
			}
			c--;
			continue;
		}

consume_moar:
		c++;
		switch (*c) {
		case '0': {
			c++;
			min_len = *c - '0';
			goto consume_moar;
		} break;
		case 's': {
			char *s = __builtin_va_arg(args, char *);
			print(fd, s);
		} break;
		case 'd': {
			i64 i = __builtin_va_arg(args, i64);
			putn(fd, i, 10);
		} break;
		case 'x': {
			u64 i = __builtin_va_arg(args, u64);

			uint8_t tbuf[64];
			int sz = itoa(i, 16, tbuf);

			int pad_sz = min_len - (sz - 1);
			while (pad_sz > 0) {
				putc(fd, '0');
				pad_sz--;
			}

			write(fd, tbuf, sz - 1);
			min_len = 0;
		} break;
		case 'b': {
			u64 i = __builtin_va_arg(args, u64);
			print(fd, "0b");
			putn(fd, i, 2);
		} break;
		}
	}

	__builtin_va_end(args);
}

#define printf(...) do { dprintf(1, __VA_ARGS__); } while (0)

int memeq(const void *dst, const void *src, size_t n) {
	const char *_dst = dst;
	const char *_src = src;
	for (int i = 0; i < n; i++) {
		if (_src[i] != _dst[i]) {
			return 0;
		}
	}

	return 1;
}

void *memcpy(void *dst, const void *src, size_t n) {
	char *_dst = dst;
	const char *_src = src;
	for (int i = n; i >= 0; i--) {
		_dst[i] = _src[i];
	}

	return dst;
}

int main(int, char **);

void __main(int argc, char **argv) {
	int ret = main(argc, argv);
	exit(ret);
}
