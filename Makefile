all:
	cc -O3 -std=c99 -Wall -Wno-unused-function -o toss toss.c
	cc -O3 -std=c99 -Wall -Wno-unused-function -o catch catch.c

clean:
	rm -f *.o toss catch
