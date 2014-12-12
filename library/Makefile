.PHONY: all install clean

CFLAGS	= -D_GNU_SOURCE -fPIC

LIBDIR ?= /usr/lib64
INCDIR ?= /usr/include

VIRTIO_OBJS	= protocol.o virtio.o
SSH_OBJS	= ssh.o
SERIAL_OBJS	= protocol.o serial.o

all: virtio.so ssh.so serial.so

virtio.so: twopence.h protocol.h $(VIRTIO_OBJS)
	$(CC) $(CFLAGS) -o $@ --shared -Wl,-soname,libtwopence_$@.0 $(VIRTIO_OBJS)

ssh.so: twopence.h protocol.h $(SSH_OBJS)
	$(CC) $(CFLAGS) -o $@ --shared -Wl,-soname,libtwopence_$@.0 $(SSH_OBJS) -lssh

serial.so: twopence.h protocol.h $(SERIAL_OBJS)
	$(CC) $(CFLAGS) -o $@ --shared -Wl,-soname,libtwopence_$@.0 $(SERIAL_OBJS)

install: virtio.so ssh.so serial.so twopence.h
	mkdir -p $(DESTDIR)$(LIBDIR)
	cp virtio.so $(DESTDIR)$(LIBDIR)/libtwopence_virtio.so.0.2.0
	cp ssh.so    $(DESTDIR)$(LIBDIR)/libtwopence_ssh.so.0.2.0
	cp serial.so $(DESTDIR)$(LIBDIR)/libtwopence_serial.so.0.2.0
	mkdir -p $(DESTDIR)$(INCDIR)
	cp twopence.h $(DESTDIR)$(INCDIR)

clean:
	rm -f *.o
	rm -f virtio.so
	rm -f ssh.so
	rm -f serial.so

