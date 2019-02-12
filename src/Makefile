.POSIX:
CC     = cc
CP	   = cp

#CFLAGS = -std=c99 -D_POSIX_C_SOURCE=200112L -Wall -O1 -g3 -g -funwind-tables -I inc 
CFLAGS = -std=c99 -D_POSIX_C_SOURCE=200112L -Wall -g3 -g -funwind-tables -I ../inc \
		-Wno-missing-field-initializers -Wno-missing-braces -Wno-unused-parameter \
		-Wno-unused-variable -Wextra
		
LDFLAGS= -lpthread

all: mvx_monitor 
	$(CP) $< ../

mvx_monitor: main.c monitor.c msg_socket.c ptrace.c
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ main.c monitor.c msg_socket.c ptrace.c $(LDFLAGS)

clean:
	rm -f mvx_monitor
