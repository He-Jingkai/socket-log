all:
	gcc -c -fPIC  rw.c
	gcc -shared -fPIC -o rw.so rw.o -ldl
	rm rw.o