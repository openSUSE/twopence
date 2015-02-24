.PHONY: all install clean

ARCH      ?= x86_64
RBVERSION ?= 2.1.0
LIBDIR    ?= /usr/lib64
INCDIR    ?= /usr/include
RBDIR      = $(LIBDIR)/ruby/gems/$(RBVERSION)

all: twopence-0.3.1.gem

twopence-0.3.1.gem: twopence.gemspec Rakefile ext/twopence/extconf.rb \
                    ext/twopence/glue.c ext/twopence/target.h ext/twopence/target.c \
                    ../library/twopence.h ../library/buffer.h
	gem build twopence.gemspec

install: twopence-0.3.1.gem
	ln -sf $(DESTDIR)$(LIBDIR)/libtwopence.so.0.3.1 $(DESTDIR)$(LIBDIR)/libtwopence.so
	CFLAGS="-I$(DESTDIR)$(INCDIR)" \
	  LDFLAGS="-L$(DESTDIR)$(LIBDIR)" \
	  gem install --local --install-dir $(DESTDIR)$(RBDIR)/ -V --force twopence-0.3.1.gem
	rm $(DESTDIR)$(LIBDIR)/libtwopence.so
	rm -f $(DESTDIR)$(RBDIR)/extensions/$(ARCH)-linux/$(RBVERSION)/twopence-0.3.1/gem.build_complete
	rm -f $(DESTDIR)$(RBDIR)/gems/twopence-0.3.1/ext/twopence/siteconf*.rb

clean:
	rm -f ext/library/twopence.h
	rm -f ext/library/buffer.h
	rm -f ruby/ext/twopence/Makefile
	rm -f ruby/ext/twopence/mkmf.log
	rm -f twopence-0.3.1.gem
