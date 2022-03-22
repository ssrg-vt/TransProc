all: loop

loop: loop.c
	gcc -static -o $@ $< -lpthread

clean:
	rm -rf loop
