#include "../minilib.c"

_Thread_local int foobar = 0;

int main(int argc, char **argv) {
	foobar = 1;

	printf("foobar: %d\n", foobar);
	return 0;
}
