.PHONY: all install clean

CFLAGS	+= -I../library
LINK	+= -L../library -ltwopence -ldl

BINDIR ?= /usr/bin
MANDIR ?= /usr/share/man

all: command inject extract exit

command: command.c ../util/util.c ../util/util.h ../library/twopence.h
	$(CC) $(CFLAGS) command.c ../util/util.c $(LINK) -o command

inject: inject.c ../util/util.c ../util/util.h ../library/twopence.h
	$(CC) $(CFLAGS) inject.c ../util/util.c $(LINK) -o inject

extract: extract.c ../util/util.c ../util/util.h ../library/twopence.h
	$(CC) $(CFLAGS) extract.c ../util/util.c $(LINK) -o extract

exit: exit.c ../util/util.c ../util/util.h ../library/twopence.h
	$(CC) $(CFLAGS) exit.c ../util/util.c $(LINK) -o exit

install: command inject extract exit command.1 inject.1 extract.1 exit.1
	mkdir -p $(DESTDIR)$(BINDIR)
	cp command $(DESTDIR)$(BINDIR)/twopence_command
	cp inject $(DESTDIR)$(BINDIR)/twopence_inject
	cp extract $(DESTDIR)$(BINDIR)/twopence_extract
	cp exit $(DESTDIR)$(BINDIR)/twopence_exit
	mkdir -p $(DESTDIR)$(MANDIR)/man1
	gzip -c command.1 > $(DESTDIR)$(MANDIR)/man1/twopence_command.1.gz
	gzip -c inject.1 > $(DESTDIR)$(MANDIR)/man1/twopence_inject.1.gz
	gzip -c extract.1 > $(DESTDIR)$(MANDIR)/man1/twopence_extract.1.gz
	gzip -c exit.1 > $(DESTDIR)$(MANDIR)/man1/twopence_exit.1.gz

clean:
	rm -f command
	rm -f inject
	rm -f extract
	rm -f exit

