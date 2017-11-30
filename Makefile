CROSS=$(HOME)/cross/x86_64-elf/bin

CC=gcc
CC_OPT=-Wall -Wextra -O2
CC_CROSS=$(CROSS)/x86_64-elf-gcc
CC_CROSS_OPT=$(CC_OPT) -ffreestanding -mcmodel=large -fno-asynchronous-unwind-tables


all: test.o elfloader
run: all
	./elfloader test.o

elfloader: elfloader.c
	$(CC) $(CC_OPT) -o elfloader elfloader.c

test.o: test.c
	$(CC_CROSS) $(CC_CROSS_OPT) -c test.c -o test.o

clean:
	rm -f test.o
	rm -f elfloader

objinfo: test.o
	greadelf -a test.o
	gobjdump -Mintel -d -t test.o
