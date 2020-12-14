.PHONY: all install clean

MACOS  := $(shell sw_vers             2>/dev/null | grep 'macOS' >/dev/null && echo "true" || echo "false")

ifdef RPM_OPT_FLAGS
CCOPT	= $(RPM_OPT_FLAGS)
else
CCOPT	= -Wall -O2 -g
endif

CFLAGS	= -I../library $(CCOPT)
LINK	+= -L../library -ltwopence

BINDIR ?= /usr/local/bin
MANDIR ?= /usr/share/man

all: command inject extract exit

command: command.c shell.h ../library/twopence.h
	$(CC) $(CFLAGS) command.c $(LINK) -o command

inject: inject.c shell.h ../library/twopence.h
	$(CC) $(CFLAGS) inject.c $(LINK) -o inject

extract: extract.c shell.h ../library/twopence.h
	$(CC) $(CFLAGS) extract.c $(LINK) -o extract

exit: exit.c shell.h ../library/twopence.h
	$(CC) $(CFLAGS) exit.c $(LINK) -o exit

install: command inject extract exit command.1 inject.1 extract.1 exit.1
	mkdir -p $(DESTDIR)$(BINDIR)
	cp command $(DESTDIR)$(BINDIR)/twopence_command
	cp inject $(DESTDIR)$(BINDIR)/twopence_inject
	cp extract $(DESTDIR)$(BINDIR)/twopence_extract
	cp exit $(DESTDIR)$(BINDIR)/twopence_exit
ifeq ($(MACOS),false)
	../instman.sh -z -d "$(DESTDIR)" -p twopence_ *.1
endif

clean:
	rm -f command
	rm -f inject
	rm -f extract
	rm -f exit

