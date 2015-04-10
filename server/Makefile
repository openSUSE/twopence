.PHONY: all install clean

ifdef RPM_OPT_FLAGS
CCOPT	= $(RPM_OPT_FLAGS)
else
CCOPT	= -Wall -O2 -g
endif

BINDIR ?= /usr/bin
SERVER	= twopence_test_server
OBJS	= main.o \
	  server.o

CFLAGS	= -D_GNU_SOURCE -I../library $(CCOPT)
LIBS	= -L../library -ltwopence

all: $(SERVER)

$(SERVER): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LIBS)

install: $(SERVER)
	mkdir -p $(DESTDIR)$(BINDIR)
	install -m555 $(SERVER) $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)$(MANDIR)/man1
	gzip -c server.1 > $(DESTDIR)$(MANDIR)/man1/twopence_test_server.1.gz

clean:
	rm -f $(SERVER) *.o
