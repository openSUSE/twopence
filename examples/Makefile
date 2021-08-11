.PHONY: all install clean

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

all:

install:
	mkdir -p $(DESTDIR)/$(TWOPENCE_DIR)
	cp example.sh $(DESTDIR)/$(TWOPENCE_DIR)/
	cp example.rb $(DESTDIR)/$(TWOPENCE_DIR)/
	cp example.py $(DESTDIR)/$(TWOPENCE_DIR)/

clean:

