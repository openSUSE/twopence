.PHONY: all install clean

LIBDIR ?= /usr/lib64

all: twopence-0.3.0.gem

twopence-0.3.0.gem: twopence.gemspec Rakefile ext/twopence/extconf.rb \
                    ext/twopence/glue.c ext/twopence/target.h ext/twopence/target.c
	gem build twopence.gemspec

install: twopence-0.3.0.gem
	CFLAGS="-I$(DESTDIR)/usr/include" \
	LDFLAGS="-L$(DESTDIR)/usr/lib64" \
	gem install --local --install-dir $(DESTDIR)$(LIBDIR)/ruby/gems/2.1.0/ twopence-0.3.0.gem
	cp twopence.gemspec $(DESTDIR)$(LIBDIR)/ruby/gems/2.1.0/gems/twopence-0.3.0
	cp Rakefile $(DESTDIR)$(LIBDIR)/ruby/gems/2.1.0/gems/twopence-0.3.0

clean:
	rm -f ext/library/twopence.h
	rm -f ruby/ext/twopence/Makefile
	rm -f ruby/ext/twopence/mkmf.log
	rm -f twopence-0.3.0.gem
