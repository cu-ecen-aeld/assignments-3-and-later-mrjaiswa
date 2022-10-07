INCLUDE_DIRS = 
LIB_DIRS = 

CC=$(CROSS_COMPILE)gcc
CFLAGS = -g 
all:aesdsocket

clean:
	rm -f *.o aesdsocket *.elf *.map

aesdsocket:
	$(CC) $(CFLAGS)  -c -o aesdsocket.o aesdsocket.c
	$(CC) $(CFLAGS) -I/ aesdsocket.o -o aesdsocket
