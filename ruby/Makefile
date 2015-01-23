.PHONY: all install clean

RBVERSION ?= 2.1.0
LIBDIR    ?= /usr/lib64
INCDIR    ?= /usr/include
RBDIR      = $(LIBDIR)/ruby/gems/$(RBVERSION)

all: twopence-0.3.0.gem

twopence-0.3.0.gem: twopence.gemspec Rakefile ext/twopence/extconf.rb \
                    ext/twopence/glue.c ext/twopence/target.h ext/twopence/target.c \
                    ../library/twopence.h
	gem build twopence.gemspec

install: twopence-0.3.0.gem
	ln -s $(DESTDIR)$(LIBDIR)/libtwopence.so.0.3.0 $(DESTDIR)$(LIBDIR)/libtwopence.so
	CFLAGS="-I$(DESTDIR)$(INCDIR)" \
	  LDFLAGS="-L$(DESTDIR)$(LIBDIR)" \
	  gem install --local --install-dir $(DESTDIR)$(RBDIR)/ -V --force twopence-0.3.0.gem
	rm $(DESTDIR)$(LIBDIR)/libtwopence.so

clean:
	rm -f ext/library/twopence.h
	rm -f ruby/ext/twopence/Makefile
	rm -f ruby/ext/twopence/mkmf.log
	rm -f twopence-0.3.0.gem
