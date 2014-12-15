.PHONY: all install clean

ifdef RPM_OPTIMIZE
CCOPT	= $(RPM_OPTIMIZE)
else
CCOPT	= -Wall -O2 -g
endif

CFLAGS	= -D_GNU_SOURCE -fPIC $(CCOPT)

LIBDIR ?= /usr/lib64
INCDIR ?= /usr/include

LIB_OBJS	= twopence.o ssh.o virtio.o serial.o protocol.o

all: libtwopence.so

libtwopence.so: twopence.h $(LIB_OBJS) Makefile
	$(CC) $(CFLAGS) -o $@ --shared -Wl,-soname,libtwopence.so.0 $(LIB_OBJS) -lssh

install: libtwopence.so twopence.h
	mkdir -p $(DESTDIR)$(LIBDIR)
	cp libtwopence.so $(DESTDIR)$(LIBDIR)/libtwopence.so.0.2.2
	mkdir -p $(DESTDIR)$(INCDIR)
	cp twopence.h $(DESTDIR)$(INCDIR)

clean:
	rm -f *.o *.so

