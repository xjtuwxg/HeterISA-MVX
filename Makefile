.POSIX:
CC     = cc
CFLAGS = -std=c99 -D_POSIX_C_SOURCE=200112L -Wall -Wextra -O3 -g3 \
		-Wno-missing-field-initializers -Wno-missing-braces -Wno-unused-parameter -Wno-unused-result \
		-g -funwind-tables -I inc
LDFLAGS= -lpthread

all: clean mvx_monitor testall

mvx_monitor: main.c monitor.c msg_socket.c ptrace.c
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ main.c monitor.c msg_socket.c ptrace.c $(LDFLAGS)

testall:
	$(MAKE) -C test

clean:
	rm -f mvx_monitor
	$(MAKE) -C test clean
