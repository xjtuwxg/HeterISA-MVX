MUSL-CC = musl-gcc

all: basic basic-musl

basic: basic.c
	$(CC) -o $@ $< 

basic-musl: basic.c
	$(MUSL-CC) -o $@ $<

clean:
	rm -f basic basic-musl
