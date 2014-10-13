.PHONY: all install clean

LIBDIR ?= /usr/lib64
INCDIR ?= /usr/include

all: virtio.so ssh.so serial.so

virtio.so: protocol.c virtio.c twopence.h
	gcc --shared -fPIC -Wl,-soname,libtwopence_virtio.so.0 virtio.c protocol.c -o virtio.so

ssh.so: ssh.c twopence.h
	gcc --shared -fPIC -Wl,-soname,libtwopence_ssh.so.0    ssh.c    -lssh      -o ssh.so

serial.so: protocol.c serial.c twopence.h
	gcc --shared -fPIC -Wl,-soname,libtwopence_serial.so.0 serial.c protocol.c -o serial.so

install: virtio.so ssh.so serial.so twopence.h
	mkdir -p $(DESTDIR)$(LIBDIR)
	cp virtio.so $(DESTDIR)$(LIBDIR)/libtwopence_virtio.so.0.1.7
	cp ssh.so    $(DESTDIR)$(LIBDIR)/libtwopence_ssh.so.0.1.7
	cp serial.so $(DESTDIR)$(LIBDIR)/libtwopence_serial.so.0.1.7
	mkdir -p $(DESTDIR)$(INCDIR)
	cp twopence.h $(DESTDIR)$(INCDIR)

clean:
	rm -f virtio.so
	rm -f ssh.so
	rm -f serial.so

