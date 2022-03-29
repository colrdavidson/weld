set -eux

BUILDDIR=build
rm -rf $BUILDDIR
mkdir $BUILDDIR

nasm -f elf64 crtstub.S -o $BUILDDIR/crtstub.o
clang -o $BUILDDIR/main.o -nostdlib -O3 -c main.c
clang -o linker -nostdlib -static -O3 $BUILDDIR/crtstub.o $BUILDDIR/main.o
clang -o $BUILDDIR/test.o -c tests/test.c
