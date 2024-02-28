TARGET := aesdsocket

CFLAGS ?= -g -Wall -Werror -pthread
# Must be after source files on Ubuntu 20.04 and older (i.e. use LDLIBS not LDFLAGS)
LDLIBS ?= -lrt

USE_AESD_CHAR_DEVICE ?= 1

ifeq ($(USE_AESD_CHAR_DEVICE),1)
  DEFINES += -DUSE_AESD_CHAR_DEVICE
endif

override CFLAGS := $(CFLAGS) $(DEFINES)

.PHONY: all
all: $(TARGET)

# Use default rule %: %.c (see make -p)
$(TARGET): $(TARGET).c

.PHONY: clean
clean:
	-${RM} $(TARGET)
