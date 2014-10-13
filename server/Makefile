.PHONY: all install clean

all: twopence_test_server

twopence_test_server: test_server.c
	gcc test_server.c -o twopence_test_server

install: twopence_test_server
	mkdir -p $(DESTDIR)/usr/lib/twopence
	cp twopence_test_server $(DESTDIR)/usr/lib/twopence/

clean:
	rm -f twopence_test_server
