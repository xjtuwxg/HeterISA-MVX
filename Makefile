all: clean main testall 

main:
	$(MAKE) -C src 

testall:
	$(MAKE) -C test

clean:
	$(MAKE) -C src clean
	$(MAKE) -C test clean
