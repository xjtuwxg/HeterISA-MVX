MUSL-CC = musl-gcc
CFLAGS	= -static
all: basic epoll

basic: basic.c
	$(MUSL-CC) $(CFLAGS) -o $@ $<

epoll: epoll.c
	$(MUSL-CC) $(CFLAGS) -o $@ $<

clean:
	rm -f basic epoll
