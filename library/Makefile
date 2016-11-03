.PHONY: all install clean

DEBIAN := $(shell cat /etc/os-release | grep 'Debian' >/dev/null && echo "true" || echo "false")
FEDORA := $(shell cat /etc/os-release | grep 'Fedora' >/dev/null && echo "true" || echo "false")
SUSE   := $(shell cat /etc/os-release | grep 'SUSE' >/dev/null && echo "true" || echo "false")
UBUNTU := $(shell cat /etc/os-release | grep 'Ubuntu' >/dev/null && echo "true" || echo "false")

VERSION:= $(shell ../subst.sh --version)

ifdef RPM_OPT_FLAGS
CCOPT	= $(RPM_OPT_FLAGS)
else
CCOPT	= -Wall -O2 -g
endif

CFLAGS	= -D_GNU_SOURCE -fPIC $(CCOPT)

ifeq ($(UBUNTU),true)
  LIBDIR  ?= /usr/lib/x86_64-linux-gnu
else
  LIBDIR  ?= /usr/lib64
endif
INCDIR ?= /usr/include
MANDIR ?= /usr/share/man

LIB_OBJS= twopence.o \
	  ssh.o \
	  virtio.o \
	  serial.o \
	  tcp.o \
	  chroot.o \
	  pipe.o \
	  transaction.o \
	  protocol.o \
	  connection.o \
	  iostream.o \
	  socket.o \
	  timer.o \
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
	../instman.sh -z -d "$(DESTDIR)" twopence.3

version.h: version.h.in
	../subst.sh < $< > $@

clean:
	rm -f *.o *.so
	rm -f version.h
