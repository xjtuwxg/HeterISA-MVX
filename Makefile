.POSIX:
CC     = cc
MUSL-CC = musl-gcc
CFLAGS = -std=c99 -Wall -Wextra -O3 -g3 \
		-Wno-missing-field-initializers -Wno-missing-braces -g -funwind-tables -I inc

all: mvx_monitor test

mvx_monitor: monitor.c msg_socket.c ptrace.c
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ monitor.c msg_socket.c ptrace.c

test: test.c
	$(CC) -o $@ test.c 
	$(MUSL-CC) -o test-musl test.c 


clean:
	rm -f mvx_monitor test test-musl
