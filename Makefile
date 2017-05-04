all:
	cc -O3 -s -std=c99 -Wall -o toss toss.c
	cc -O3 -s -std=c99 -Wall -o catch catch.c

clean:
	rm -f *.o toss catch
