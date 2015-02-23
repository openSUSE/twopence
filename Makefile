.PHONY: all install clean \
        library server ruby shell examples tests \
        library-install server-install ruby-install shell-install examples-install \
        library-clean server-clean ruby-clean shell-clean examples-clean

SUBDIRS = \
	library \
	server \
	ruby \
	python \
	shell \
	tests \
	examples

all clean install::
	@for dir in $(SUBDIRS); do \
		echo "make -C $$dir $@"; make -C $$dir $@ || exit 1; \
	done

install::
	mkdir -p $(DESTDIR)/usr/lib/twopence-0
	cp add_virtio_channel.sh $(DESTDIR)/usr/lib/twopence-0/

tests: server shell
	make -C tests $@
