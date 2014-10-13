.PHONY: all install clean \
        library server ruby shell examples \
        library-install server-install ruby-install shell-install examples-install \
        library-clean server-clean ruby-clean shell-clean examples-clean

all: library server ruby shell examples

library:
	make -C library all

server:
	make -C server all

ruby:
	make -C ruby all

shell:
	make -C shell all

examples:
	make -C examples all

install: library-install server-install ruby-install shell-install examples-install
	mkdir -p $(DESTDIR)/usr/lib/twopence
	cp add_virtio_channel.sh $(DESTDIR)/usr/lib/twopence/

library-install:
	make -C library install

server-install:
	make -C server install

ruby-install:
	make -C ruby install

shell-install:
	make -C shell install

examples-install:
	make -C examples install

clean: library-clean server-clean ruby-clean shell-clean examples-clean

library-clean:
	make -C library clean

server-clean:
	make -C server clean

ruby-clean:
	make -C ruby clean

shell-clean:
	make -C shell clean

examples-clean:
	make -C examples clean

