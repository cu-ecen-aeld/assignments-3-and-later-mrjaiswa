INCLUDE_DIRS = 
LIB_DIRS = 
CC=gcc


CFLAGS = -g 
all:aesdsocket

	$(CROSS_COMPILE)$(CC) aesdsocket.c -o aesdsocket 
clean:
	rm -f *.o aesdsocket *.elf *.map

aesdsocket:
	$(CC) $(CFLAGS)  -c -o aesdsocket.o aesdsocket.c
	$(CC) $(CFLAGS) -I/ aesdsocket.o -o aesdsocket
