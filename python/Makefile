
CFLAGS	= -fPIC -I/usr/include/python2.7 -I../library -Wall -g
PYDIR  ?= /usr/lib64/python2.6/site-packages
OBJS	= extension.o \
	  command.o \
	  config.o \
	  status.o \
	  target.o


all:	twopence.so

twopence.so: $(OBJS)
	$(CC) --shared -o $@ $(OBJS) -L../library -ltwopence

clean:
	rm -f *.o *.so

install:
	mkdir -p $(DESTDIR)$(PYDIR)
	cp twopence.so $(DESTDIR)$(PYDIR)
