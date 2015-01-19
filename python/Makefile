CFLAGS	= -fPIC -I/usr/include/python -I../library -Wall -g
PYDIR  ?= /usr/lib64/python/site-packages
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
