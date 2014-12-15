.PHONY: all install clean

ifdef RPM_OPTIMIZE
CCOPT	= $(RPM_OPTIMIZE)
else
CCOPT	= -Wall -O2 -g
endif

CFLAGS	= -D_GNU_SOURCE $(CCOPT)

all: twopence_test_server

twopence_test_server: test_server.o
	$(CC) test_server.o -o twopence_test_server

install: twopence_test_server
	mkdir -p $(DESTDIR)/usr/lib/twopence
	cp twopence_test_server $(DESTDIR)/usr/lib/twopence/

clean:
	rm -f twopence_test_server *.o
