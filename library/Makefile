.PHONY: all install clean

VERSION	= 0.3.5

ifdef RPM_OPT_FLAGS
CCOPT	= $(RPM_OPT_FLAGS)
else
CCOPT	= -Wall -O2 -g
endif

CFLAGS	= -D_GNU_SOURCE -fPIC $(CCOPT)

LIBDIR ?= /usr/lib64
INCDIR ?= /usr/include
MANDIR ?= /usr/share/man

LIB_OBJS= twopence.o \
	  ssh.o \
	  virtio.o \
	  serial.o \
	  tcp.o \
	  pipe.o \
	  transaction.o \
	  protocol.o \
	  connection.o \
	  iostream.o \
	  socket.o \
	  buffer.o \
	  logging.o \
	  utils.o
HEADERS	= buffer.h \
	  twopence.h \
	  version.h

all: libtwopence.so

libtwopence.so: $(HEADERS) $(LIB_OBJS) Makefile
	$(CC) $(CFLAGS) -o $@ --shared -Wl,-soname,libtwopence.so.0 $(LIB_OBJS) -lssh

install: libtwopence.so $(HEADERS)
	mkdir -p $(DESTDIR)$(LIBDIR)
	install -m555 libtwopence.so $(DESTDIR)$(LIBDIR)/libtwopence.so.$(VERSION)
	mkdir -p $(DESTDIR)$(INCDIR)/twopence
	install -m444 $(HEADERS) $(DESTDIR)$(INCDIR)/twopence
	mkdir -p $(DESTDIR)$(MANDIR)/man3
	gzip -c twopence.3 > $(DESTDIR)$(MANDIR)/man3/twopence.3.gz

version.h: version.h.in
	sed 's:@VERSION@:$(VERSION):g' $< > $@

clean:
	rm -f *.o *.so
	rm -f version.h
