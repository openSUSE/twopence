.PHONY: all install clean

RBVERSION ?= 2.1.0
LIBDIR    ?= /usr/lib64
INCDIR    ?= /usr/include
RBDIR      = $(LIBDIR)/ruby/gems/$(RBVERSION)

all: twopence-0.3.0.gem

twopence-0.3.0.gem: twopence.gemspec Rakefile ext/twopence/extconf.rb \
                    ext/twopence/glue.c ext/twopence/target.h ext/twopence/target.c \
                    ../library/twopence.h
	cp ../library/twopence.h ext/library/
	gem build twopence.gemspec

install: twopence-0.3.0.gem
	ln -s $(DESTDIR)$(LIBDIR)/libtwopence.so.0.3.0 $(DESTDIR)$(LIBDIR)/libtwopence.so
	CFLAGS="-I$(DESTDIR)$(INCDIR)" \
	  LDFLAGS="-L$(DESTDIR)$(LIBDIR)" \
	  gem install --local --install-dir $(DESTDIR)$(RBDIR)/ -V --force twopence-0.3.0.gem
	#
	# comment out the following lines if you want to be able to rebuild the gem on the target system:
	rm $(DESTDIR)$(LIBDIR)/libtwopence.so
	rm $(DESTDIR)$(RBDIR)/gems/twopence-0.3.0/ext/twopence/.RUBYARCHDIR.time
	rm $(DESTDIR)$(RBDIR)/gems/twopence-0.3.0/ext/twopence/extconf.rb
	rm $(DESTDIR)$(RBDIR)/gems/twopence-0.3.0/ext/twopence/target.h
	rm $(DESTDIR)$(RBDIR)/gems/twopence-0.3.0/ext/twopence/target.c
	rm $(DESTDIR)$(RBDIR)/gems/twopence-0.3.0/ext/twopence/glue.c
	rm $(DESTDIR)$(RBDIR)/gems/twopence-0.3.0/ext/library/twopence.h

clean:
	rm -f ext/library/twopence.h
	rm -f ruby/ext/twopence/Makefile
	rm -f ruby/ext/twopence/mkmf.log
	rm -f twopence-0.3.0.gem
