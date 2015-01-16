PYVERSION ?= 2.6
CFLAGS	   = -fPIC -I/usr/include/python${PYVERSION} -I../library -Wall -g
PYDIR	  ?= /usr/lib64/python${PYVERSION}/site-packages
OBJS	   = extension.o \
	     command.o \
	     status.o \
	     target.o

all: twopence.so

twopence.so: $(OBJS)
	$(CC) --shared -o $@ $(OBJS) -L../library -ltwopence

clean:
	rm -f *.o *.so

install:
	mkdir -p $(DESTDIR)$(PYDIR)
	cp twopence.so $(DESTDIR)$(PYDIR)
