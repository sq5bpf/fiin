default: fiin
fiin: fiin.c
	cc fiin.c -o fiin -O2 
clean:
	rm -f fiin *~
indent:
	indent fiin.c
install: 
	cp fiin /usr/local/bin
 
