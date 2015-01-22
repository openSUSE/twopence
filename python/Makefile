PYVERSION ?= 2.6
LIBDIR	  ?= /usr/lib64
CFLAGS	   = -fPIC -I/usr/include/python${PYVERSION} -I../library -Wall -g
OBJS	   = extension.o \
	     command.o \
	     status.o \
	     target.o
PYDIR	   = ${LIBDIR}/python${PYVERSION}/site-packages

all: twopence.so

twopence.so: $(OBJS)
	$(CC) --shared -o $@ $(OBJS) -L../library -ltwopence

clean:
	rm -f *.o *.so

install:
	mkdir -p $(DESTDIR)$(PYDIR)
	cp twopence.so $(DESTDIR)$(PYDIR)
