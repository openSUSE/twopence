.PHONY: all install clean

ifdef RPM_OPTIMIZE
CCOPT	= $(RPM_OPTIMIZE)
else
CCOPT	= -Wall -O2 -g
endif

SERVER	= twopence_test_server
OBJS	= main.o \
	  connection.o \
	  protocol.o \
	  server.o \
	  socket.o

CFLAGS	= -D_GNU_SOURCE -I../library $(CCOPT)

all: $(SERVER)

$(SERVER): $(OBJS)
	$(CC) $(OBJS) -o $@

install: $(SERVER)
	mkdir -p $(DESTDIR)/usr/lib/twopence
	install -m555 $(SERVER) $(DESTDIR)/usr/bin

clean:
	rm -f $(SERVER) *.o
