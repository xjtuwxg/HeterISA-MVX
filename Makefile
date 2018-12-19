.POSIX:
CC     = cc
#CFLAGS = -std=c99 -D_POSIX_C_SOURCE=200112L -Wall -O1 -g3 -g -funwind-tables -I inc 
CFLAGS = -std=c99 -D_POSIX_C_SOURCE=200112L -Wall -g3 -g -funwind-tables -I inc \
		-Wno-missing-field-initializers -Wno-missing-braces -Wno-unused-parameter \
		-Wno-unused-variable -Wextra
		
LDFLAGS= -lpthread

all: clean mvx_monitor testall

mvx_monitor: main.c monitor.c msg_socket.c ptrace.c
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ main.c monitor.c msg_socket.c ptrace.c $(LDFLAGS)

debug_monitor: skeleton.c monitor.c msg_socket.c ptrace.c
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ skeleton.c monitor.c msg_socket.c ptrace.c $(LDFLAGS)

testall:
	$(MAKE) -C test

clean:
	rm -f mvx_monitor debug_monitor
	$(MAKE) -C test clean
