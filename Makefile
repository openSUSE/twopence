.PHONY: all install clean \
        library server ruby shell examples tests \
        library-install server-install ruby-install shell-install examples-install \
        library-clean server-clean ruby-clean shell-clean examples-clean

DEBIAN := $(shell cat /etc/os-release 2>/dev/null | grep 'Debian' >/dev/null && echo "true" || echo "false")
FEDORA := $(shell cat /etc/os-release 2>/dev/null | grep 'Fedora' >/dev/null && echo "true" || echo "false")
SUSE   := $(shell cat /etc/os-release 2>/dev/null | grep 'SUSE' >/dev/null && echo "true" || echo "false")
UBUNTU := $(shell cat /etc/os-release 2>/dev/null | grep 'Ubuntu' >/dev/null && echo "true" || echo "false")
MACOS  := $(shell sw_vers             2>/dev/null | grep 'macOS' >/dev/null && echo "true" || echo "false")

ifeq ($(MACOS),true)
  TWOPENCE_DIR = /usr/local/lib/twopence-0
else
  TWOPENCE_DIR = /usr/lib/twopence-0
endif

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
	mkdir -p $(DESTDIR)/$(TWOPENCE_DIR)
	cp add_virtio_channel.sh $(DESTDIR)/$(TWOPENCE_DIR)/

tests: server shell
	make -C tests $@
