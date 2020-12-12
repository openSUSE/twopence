.PHONY: all install clean

MACOS  := $(shell sw_vers             2>/dev/null | grep 'macOS' >/dev/null && echo "true" || echo "false")

ifdef RPM_OPT_FLAGS
CCOPT	= $(RPM_OPT_FLAGS)
else
CCOPT	= -Wall -O2 -g
endif

BINDIR ?= /usr/local/bin

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
ifeq ($(MACOS),false)
	../instman.sh -z -d "$(DESTDIR)" -n twopence_test_server.1 server.1
endif

clean:
	rm -f $(SERVER) *.o
