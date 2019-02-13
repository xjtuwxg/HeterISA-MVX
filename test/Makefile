MUSL-CC = musl-gcc
CFLAGS	= -static
all: basic epoll tiny

basic: basic.c
	$(MUSL-CC) $(CFLAGS) -o $@ $<

epoll: epoll.c
	$(MUSL-CC) $(CFLAGS) -o $@ $<

clean:
	rm -f basic epoll

lighttpd:
	../mvx_monitor /opt/lighttpd/sbin/lighttpd -f lighttpd.conf -D

curl:
	./curl.sh

ab:
	ab -n 1000 -c 10 127.0.0.1:8889/index.html
