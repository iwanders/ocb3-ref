options = 

all:
	gcc $(options) -c -o main.o main.c
	gcc $(options) -c -o ocb.o ../ocb.c
	gcc $(options) -c -o rijndael-alg-fst.o ../rijndael-alg-fst.c
	gcc $(options) -o main  main.o ocb.o rijndael-alg-fst.o


clean:
	rm -f *.o *.d main
