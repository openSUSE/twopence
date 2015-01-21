.PHONY: all install clean \
        library server ruby shell examples \
        library-install server-install ruby-install shell-install examples-install \
        library-clean server-clean ruby-clean shell-clean examples-clean

SUBDIRS = \
	library \
	server \
	ruby \
	python \
	shell \
	examples

all clean install::
	@for dir in $(SUBDIRS); do \
		echo "make -C $$dir $@"; make -C $$dir $@ || exit 1; \
	done

install::
	mkdir -p $(DESTDIR)/usr/lib/twopence
	cp add_virtio_channel.sh $(DESTDIR)/usr/lib/twopence/

tests:
	set -e; for plugin in virtio; do \
		examples/run-$$plugin examples/test.sh; \
	done
