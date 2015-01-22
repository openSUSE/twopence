.PHONY: all install clean

ifdef RPM_OPTIMIZE
CCOPT	= $(RPM_OPTIMIZE)
else
CCOPT	= -Wall -O2 -g
endif

CFLAGS	= -D_GNU_SOURCE $(CCOPT)

BINDIR ?= /usr/bin

all: twopence_test_server

twopence_test_server: test_server.o
	$(CC) test_server.o -o twopence_test_server

install: twopence_test_server
	mkdir -p $(DESTDIR)$(BINDIR)
	cp twopence_test_server $(DESTDIR)$(BINDIR)/
	mkdir -p $(DESTDIR)$(MANDIR)/man1
	gzip -c server.1 > $(DESTDIR)$(MANDIR)/man1/twopence_test_server.1.gz

clean:
	rm -f twopence_test_server *.o
