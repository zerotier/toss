DESTDIR?=/usr/local/bin

all:
	cc -O3 -std=c99 -Wall -Wno-unused-function -o toss toss.c
	cc -O3 -std=c99 -Wall -Wno-unused-function -o catch catch.c

clean:
	rm -rf *.o toss catch speck_test *.dSYM

distclean: clean

realclean: clean

install:
	mkdir -p $(DESTDIR)
	cp toss catch $(DESTDIR)
	chmod 0755 $(DESTDIR)/toss $(DESTDIR)/catch

uninstall:
	rm -f $(DESTDIR)/toss $(DESTDIR)/catch

speck_test:
	cc -O3 -std=c99 -o speck_test speck_test.c
