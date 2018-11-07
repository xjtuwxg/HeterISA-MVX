.POSIX:
CC     = cc
CFLAGS = -std=c99 -Wall -Wextra -O3 -g3 \
		-Wno-missing-field-initializers -Wno-missing-braces -g -funwind-tables -I include

all: mvx_monitor test

mvx_monitor: monitor.c
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ monitor.c

test: test.c
	$(CC) -o $@ test.c


clean:
	rm -f mvx_monitor test
