all:
	cc -O3 -o toss toss.c

clean:
	rm -f *.o toss catch
