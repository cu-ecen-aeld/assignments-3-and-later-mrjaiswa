INCLUDE_DIRS = 
LIB_DIRS = 
CC=gcc

CFLAGS ?= -g -Werror -Wall
LDFLAGS ?= -pthread -lrt


all:aesdsocket

	$(CROSS_COMPILE)$(CC) $(CFLAGS) $(LDFLAGS) aesdsocket.c -o aesdsocket 
clean:
	rm -f *.o aesdsocket *.elf *.map

aesdsocket:
	$(CC) $(CFLAGS)  -c -o aesdsocket.o aesdsocket.c
	$(CC) $(CFLAGS) -I/ aesdsocket.o -o aesdsocket
