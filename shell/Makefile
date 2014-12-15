.PHONY: all install clean

ifdef RPM_OPTIMIZE
CCOPT	= $(RPM_OPTIMIZE)
else
CCOPT	= -Wall -O2 -g
endif

CFLAGS	= -I../library $(CCOPT)
LINK	+= -L../library -ltwopence

BINDIR ?= /usr/bin
MANDIR ?= /usr/share/man

all: command inject extract exit

command: command.c ../library/twopence.h
	$(CC) $(CFLAGS) command.c $(LINK) -o command

inject: inject.c ../library/twopence.h
	$(CC) $(CFLAGS) inject.c $(LINK) -o inject

extract: extract.c ../library/twopence.h
	$(CC) $(CFLAGS) extract.c $(LINK) -o extract

exit: exit.c ../library/twopence.h
	$(CC) $(CFLAGS) exit.c $(LINK) -o exit

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

