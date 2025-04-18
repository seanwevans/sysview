CC = gcc
CFLAGS = -Wall -Werror -O2
LDFLAGS = -lncurses

TARGET = syscall_monitor

.PHONY: all clean

all: $(TARGET)

$(TARGET): syscall_monitor.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)
