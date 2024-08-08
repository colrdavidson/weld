set -eux

BUILDDIR=build
rm -rf $BUILDDIR
mkdir $BUILDDIR

nasm -f elf64 crtstub.S -o $BUILDDIR/crtstub.o
clang -o $BUILDDIR/main.o -g -fpic -nostdlib -Os -c main.c
ld -o weld -T link.ld --gc-sections $BUILDDIR/crtstub.o $BUILDDIR/main.o

clang -o $BUILDDIR/test.o -fpic -nostdlib -g -c tests/test.c
ld -o $BUILDDIR/test --gc-sections $BUILDDIR/crtstub.o $BUILDDIR/test.o

clang -o $BUILDDIR/test2 -fpie -Os -g tests/test2.c
