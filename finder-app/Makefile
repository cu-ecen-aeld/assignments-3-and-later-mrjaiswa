# Default compiler
# Writer Mrinal
CC = gcc
BCC = aarch64-none-linux-gnu-gcc
# Writer application
writer:
	$(CROSS_COMPILE)$(CC) -Wall -Werror writer.c -o writer

# Writer .o files
writer.o:
	$(CROSS_COMPILE)$(CC) -c writer.c

# Clean all binaries
clean:
	rm -f *.o writer
