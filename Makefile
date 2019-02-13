all: clean main testall 

main:
	$(MAKE) -C src 

testall:
	$(MAKE) -C test

curllighttpd:
	$(MAKE) -C test curl

ablighttpd:
	$(MAKE) -C test ab

clean:
	$(MAKE) -C src clean
	$(MAKE) -C test clean
