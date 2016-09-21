.PHONY: all install clean

ARCH      ?= x86_64
RBVERSION ?= 2.1.0
LIBDIR    ?= /usr/lib64
INCDIR    ?= /usr/include
VERSION   := $(shell ../subst.sh --version)
RBDIR      = $(LIBDIR)/ruby/gems/$(RBVERSION)
SUSE      := $(shell cat /etc/os-release | grep 'SUSE' >/dev/null; echo $$?)

all: twopence-$(VERSION).gem

twopence-$(VERSION).gem: twopence.gemspec Rakefile ext/twopence/extconf.rb \
                    ext/twopence/glue.c ext/twopence/target.h ext/twopence/target.c \
                    ../library/twopence.h ../library/buffer.h
	gem build twopence.gemspec

twopence.gemspec: twopence.gemspec.in
	../subst.sh < $< > $@

install: twopence-$(VERSION).gem
	ln -sf $(DESTDIR)$(LIBDIR)/libtwopence.so.$(VERSION) $(DESTDIR)$(LIBDIR)/libtwopence.so

ifeq ($(SUSE) ,0)
		echo "SUSE"
		# for suse/openSUSE spec.file
		CFLAGS="-I$(DESTDIR)$(INCDIR)" LDFLAGS="-L$(DESTDIR)$(LIBDIR)" DESTDIR="" \
		  gem install --local \
                     --build-root "$(DESTDIR)/" \
                     --install-dir "$(RBDIR)/" \
                     -V --force twopence-$(VERSION).gem
else
		CFLAGS="-I$(DESTDIR)$(INCDIR)" LDFLAGS="-L$(DESTDIR)$(LIBDIR)" DESTDIR="" \
                  gem install --local \
                     --install-dir "$(RBDIR)/" \
                     -V --force twopence-$(VERSION).gem
endif
	rm $(DESTDIR)$(LIBDIR)/libtwopence.so
	rm -f $(DESTDIR)$(RBDIR)/gems/twopence-$(VERSION)/ext/twopence/siteconf*.rb

clean:
	rm -f ext/library/twopence.h
	rm -f ext/library/buffer.h
	rm -f ruby/ext/twopence/Makefile
	rm -f ruby/ext/twopence/mkmf.log
	rm -f twopence-$(VERSION).gem
