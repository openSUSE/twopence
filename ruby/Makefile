.PHONY: all install clean

LIBDIR ?= /usr/lib64

all: twopence-0.1.7.gem

twopence-0.1.7.gem: twopence.gemspec Rakefile ext/twopence/extconf.rb \
                    ext/twopence/glue.c ../library/twopence.h ../util/util.c ../util/util.h
	cp ../library/twopence.h ext/library/
	cp ../util/util.c ext/twopence/
	cp ../util/util.h ext/twopence/
	gem build twopence.gemspec

install: twopence-0.1.7.gem
	gem install --local --install-dir $(DESTDIR)$(LIBDIR)/ruby/gems/2.0.0/ twopence-0.1.7.gem
	cp twopence.gemspec $(DESTDIR)$(LIBDIR)/ruby/gems/2.0.0/gems/twopence-0.1.7
	cp Rakefile $(DESTDIR)$(LIBDIR)/ruby/gems/2.0.0/gems/twopence-0.1.7

clean:
	rm -f ext/library/twopence.h
	rm -f ext/twopence/util.c
	rm -f ext/twopence/util.h
	rm -f ruby/ext/twopence/Makefile
	rm -f ruby/ext/twopence/mkmf.log
	rm -f twopence-0.1.7.gem
