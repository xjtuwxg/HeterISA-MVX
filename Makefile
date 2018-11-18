.POSIX:
CC     = cc
CFLAGS = -std=c99 -Wall -Wextra -O3 -g3 \
		-Wno-missing-field-initializers -Wno-missing-braces -g -funwind-tables -I inc

all: mvx_monitor testall

mvx_monitor: main.c monitor.c msg_socket.c ptrace.c
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ main.c monitor.c msg_socket.c ptrace.c

testall:
	$(MAKE) -C test

clean:
	rm -f mvx_monitor
	$(MAKE) -C test clean
