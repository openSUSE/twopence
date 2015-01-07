
CFLAGS	= -fPIC -I/usr/include/python2.6 -I../library -Wall -g

PYDIR  ?= /usr/lib64/python2.6/site-packages

all:	twopence.so

twopence.so: extension.o
	$(CC) --shared -o $@ extension.o -L../library -ltwopence

clean:
	rm -f *.o *.so

install:
	mkdir -p $(DESTDIR)$(PYDIR)
	cp twopence.so $(DESTDIR)$(PYDIR)
