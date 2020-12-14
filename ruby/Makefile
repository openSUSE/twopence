.PHONY: all install clean

DEBIAN := $(shell cat /etc/os-release 2>/dev/null | grep 'Debian' >/dev/null && echo "true" || echo "false")
FEDORA := $(shell cat /etc/os-release 2>/dev/null | grep 'Fedora' >/dev/null && echo "true" || echo "false")
SUSE   := $(shell cat /etc/os-release 2>/dev/null | grep 'SUSE' >/dev/null && echo "true" || echo "false")
UBUNTU := $(shell cat /etc/os-release 2>/dev/null | grep 'Ubuntu' >/dev/null && echo "true" || echo "false")
MACOS  := $(shell sw_vers             2>/dev/null | grep 'macOS' >/dev/null && echo "true" || echo "false")

ARCH      ?= x86_64
ifeq ($(UBUNTU),true)
  LIBDIR  ?= /usr/lib/x86_64-linux-gnu
  RBVERSION ?= 2.3.0
  RBDIR      = $(LIBDIR)/ruby/$(RBVERSION)
else ifeq ($(MACOS),true)
  LIBDIR  ?= /usr/local/lib
  RBVERSION ?= 2.7.0
  RBDIR      = $(LIBDIR)/ruby/gems/$(RBVERSION)
else
  LIBDIR  ?= /usr/lib64
  RBVERSION ?= 2.5.0
  RBDIR      = $(LIBDIR)/ruby/gems/$(RBVERSION)
endif

ifeq ($(MACOS),true)
	INCDIR    ?= /usr/local/include
else
	INCDIR    ?= /usr/include
endif

VERSION   := $(shell ../subst.sh --version)

all: twopence-$(VERSION).gem

twopence-$(VERSION).gem: twopence.gemspec Rakefile ext/twopence/extconf.rb \
                    ext/twopence/glue.c ext/twopence/target.h ext/twopence/target.c \
                    ../library/twopence.h ../library/buffer.h
	gem build twopence.gemspec

twopence.gemspec: twopence.gemspec.in ../subst.sh
	../subst.sh < $< > $@

ifeq ($(MACOS),true)
install: twopence-$(VERSION).gem
	ln -sf $(DESTDIR)$(LIBDIR)/libtwopence.0.dylib $(DESTDIR)$(LIBDIR)/libtwopence.dylib
else
install: twopence-$(VERSION).gem
	ln -sf $(DESTDIR)$(LIBDIR)/libtwopence.so.$(VERSION) $(DESTDIR)$(LIBDIR)/libtwopence.so
endif

ifeq ($(UBUNTU),true)
	CFLAGS="-I$(DESTDIR)$(INCDIR)" LDFLAGS="-L$(DESTDIR)$(LIBDIR)" DESTDIR="" \
	       gem install -V --force twopence-$(VERSION).gem
else ifeq ($(FEDORA),true)
	# There will probably be problems on Fedora when building
	# from a specfile, because we don't use $(DESTDIR)
	CFLAGS="-I$(DESTDIR)$(INCDIR)" LDFLAGS="-L$(DESTDIR)$(LIBDIR)" DESTDIR="" \
               gem install --local \
                     --install-dir "$(RBDIR)/" \
                     -V --force twopence-$(VERSION).gem
else ifeq ($(MACOS),true)
	CFLAGS="-I$(DESTDIR)$(INCDIR)" LDFLAGS="-L$(DESTDIR)$(LIBDIR)" DESTDIR="" \
	       gem install --local \
                     --build-root "$(DESTDIR)/" \
                     --install-dir "$(RBDIR)/" \
                     -V --force twopence-$(VERSION).gem
else
	CFLAGS="-I$(DESTDIR)$(INCDIR)" LDFLAGS="-L$(DESTDIR)$(LIBDIR)" DESTDIR="" \
	       gem install --local \
                     --build-root "$(DESTDIR)/" \
                     --install-dir "$(RBDIR)/" \
                     -V --force twopence-$(VERSION).gem
endif

clean:
	rm -f ext/library/twopence.h
	rm -f ext/library/buffer.h
	rm -f ruby/ext/twopence/Makefile
	rm -f ruby/ext/twopence/mkmf.log
	rm -f twopence-*.gem
