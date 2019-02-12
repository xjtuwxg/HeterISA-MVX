all: clean main testall 

main:
	$(MAKE) -C src 

testall:
	$(MAKE) -C test

testlighttpd:
	$(MAKE) -C test lighttpd

clean:
	$(MAKE) -C src clean
	$(MAKE) -C test clean
