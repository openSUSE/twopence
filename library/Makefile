.PHONY: all install clean

VERSION	= 0.3.0

ifdef RPM_OPT_FLAGS
CCOPT	= $(RPM_OPT_FLAGS)
else
CCOPT	= -Wall -O2 -g
endif

CFLAGS	= -D_GNU_SOURCE -fPIC $(CCOPT)

LIBDIR ?= /usr/lib64
INCDIR ?= /usr/include

LIB_OBJS= twopence.o config.o ssh.o virtio.o serial.o protocol.o

all: libtwopence.so

libtwopence.so: twopence.h $(LIB_OBJS) Makefile
	$(CC) $(CFLAGS) -o $@ --shared -Wl,-soname,libtwopence.so.0 $(LIB_OBJS) -lssh

install: libtwopence.so twopence.h
	mkdir -p $(DESTDIR)$(LIBDIR)
	install -m555 libtwopence.so $(DESTDIR)$(LIBDIR)/libtwopence.so.$(VERSION)
	mkdir -p $(DESTDIR)$(INCDIR)
	install -m444 twopence.h $(DESTDIR)$(INCDIR)

clean:
	rm -f *.o *.so
