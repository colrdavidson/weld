set -eux

BUILDDIR=build
rm -rf $BUILDDIR
mkdir $BUILDDIR

nasm -f elf64 crtstub.S -o $BUILDDIR/crtstub.o
clang -o $BUILDDIR/main.o -fpic -nostdlib -Os -c main.c
ld -o weld -T link.ld --gc-sections $BUILDDIR/crtstub.o $BUILDDIR/main.o
clang -o $BUILDDIR/test.o -c tests/test.c
