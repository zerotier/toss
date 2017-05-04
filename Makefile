all:
	cc -O3 -std=c99 -Wall -Wno-unused-function -o toss toss.c
	cc -O3 -std=c99 -Wall -Wno-unused-function -o catch catch.c

clean:
	rm -f *.o toss catch speck_test

install: all
	sudo mkdir -p /usr/local/bin
	sudo cp toss catch /usr/local/bin
	sudo chown 0 /usr/local/bin/toss /usr/local/bin/catch
	sudo chgrp 0 /usr/local/bin/toss /usr/local/bin/catch
	sudo chmod 0755 /usr/local/bin/toss /usr/local/bin/catch

speck_test:
	cc -O3 -o speck_test speck_test.c
