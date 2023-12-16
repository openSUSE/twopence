.PHONY: all install clean

DEBIAN := $(shell cat /etc/os-release 2>/dev/null | grep 'Debian' >/dev/null && echo "true" || echo "false")
FEDORA := $(shell cat /etc/os-release 2>/dev/null | grep 'Fedora' >/dev/null && echo "true" || echo "false")
SUSE   := $(shell cat /etc/os-release 2>/dev/null | grep 'SUSE' >/dev/null && echo "true" || echo "false")
UBUNTU := $(shell cat /etc/os-release 2>/dev/null | grep 'Ubuntu' >/dev/null && echo "true" || echo "false")

VERSION:= $(shell ../subst.sh --version)
MACOS  := $(shell sw_vers             2>/dev/null | grep 'macOS' >/dev/null && echo "true" || echo "false")

ifdef RPM_OPT_FLAGS
CCOPT	= $(RPM_OPT_FLAGS)
else
CCOPT	= -Wall -O2 -g
endif

CFLAGS	= -D_GNU_SOURCE -fPIC $(CCOPT)

ifeq ($(UBUNTU),true)
  LIBDIR  ?= /usr/lib/x86_64-linux-gnu
else ifeq ($(MACOS),true)
  LIBDIR  ?= /usr/local/lib
else
  LIBDIR  ?= /usr/lib64
endif

ifeq ($(MACOS),true)
	INCDIR ?= /usr/local/include
	CFLAGS	= -D_GNU_SOURCE -fPIC $(CCOPT) -I /opt/homebrew/include -I ext -L /opt/homebrew/lib -lssh 
else
	INCDIR ?= /usr/include
endif

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

ifeq ($(MACOS),true)
all: libtwopence.dylib

libtwopence.dylib: $(HEADERS) $(LIB_OBJS) Makefile
	$(CC) $(CFLAGS) -dynamiclib -install_name "libtwopence.0.dylib" \
    -current_version $(VERSION) -o $@ --shared -Wl, $(LIB_OBJS) -lssh -dynamiclib

install:
	cp -f libtwopence.dylib $(LIBDIR)/libtwopence.0.dylib
	ln -s $(LIBDIR)/libtwopence.0.dylib $(LIBDIR)/libtwopence.dylib
	install_name_tool -change "libtwopence.0.dylib" "$(LIBDIR)/libtwopence.0.dylib" $(LIBDIR)/libtwopence.0.dylib
	mkdir -p $(DESTDIR)$(INCDIR)/twopence
	install -m444 $(HEADERS) $(DESTDIR)$(INCDIR)/twopence
else
all: libtwopence.so

libtwopence.so: $(HEADERS) $(LIB_OBJS) Makefile
	$(CC) $(CFLAGS) -o $@ --shared -Wl,-soname,libtwopence.so.0 $(LIB_OBJS) -lssh

install: libtwopence.so $(HEADERS)
	mkdir -p $(DESTDIR)$(LIBDIR)
	install -m555 libtwopence.so $(DESTDIR)$(LIBDIR)/libtwopence.so.$(VERSION)
	mkdir -p $(DESTDIR)$(INCDIR)/twopence
	install -m444 $(HEADERS) $(DESTDIR)$(INCDIR)/twopence
	../instman.sh -z -d "$(DESTDIR)" twopence.3
endif

version.h: version.h.in ../subst.sh
	../subst.sh < $< > $@

clean:
	rm -f *.o *.so *.dylib
	rm -f version.h
