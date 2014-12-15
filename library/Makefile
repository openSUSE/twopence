.PHONY: all install clean

ifdef RPM_OPTIMIZE
CCOPT	= $(RPM_OPTIMIZE)
else
CCOPT	= -Wall -O2 -g
endif

CFLAGS	= -D_GNU_SOURCE -fPIC $(CCOPT)

LIBDIR ?= /usr/lib64
INCDIR ?= /usr/include

VIRTIO_OBJS	= protocol.o virtio.o
SSH_OBJS	= ssh.o
SERIAL_OBJS	= protocol.o serial.o
LIB_OBJS	= twopence.o

all: virtio.so ssh.so serial.so libtwopence.so

virtio.so: twopence.h protocol.h $(VIRTIO_OBJS)
	$(CC) $(CFLAGS) -o $@ --shared -Wl,-soname,libtwopence_$@.0 $(VIRTIO_OBJS)

ssh.so: twopence.h protocol.h $(SSH_OBJS)
	$(CC) $(CFLAGS) -o $@ --shared -Wl,-soname,libtwopence_$@.0 $(SSH_OBJS) -lssh

serial.so: twopence.h protocol.h $(SERIAL_OBJS)
	$(CC) $(CFLAGS) -o $@ --shared -Wl,-soname,libtwopence_$@.0 $(SERIAL_OBJS)

libtwopence.so: twopence.h $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ --shared -Wl,-soname,libtwopence.so.0 $(LIB_OBJS)

install: virtio.so ssh.so serial.so twopence.h
	mkdir -p $(DESTDIR)$(LIBDIR)
	cp virtio.so $(DESTDIR)$(LIBDIR)/libtwopence_virtio.so.0.2.0
	cp ssh.so    $(DESTDIR)$(LIBDIR)/libtwopence_ssh.so.0.2.0
	cp serial.so $(DESTDIR)$(LIBDIR)/libtwopence_serial.so.0.2.0
	mkdir -p $(DESTDIR)$(INCDIR)
	cp twopence.h $(DESTDIR)$(INCDIR)

clean:
	rm -f *.o *.so

