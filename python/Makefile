
ifdef RPM_OPT_FLAGS
CCOPT	= $(RPM_OPT_FLAGS)
else
CCOPT	= -Wall -O2 -g
endif

CFLAGS	= -fPIC -I/usr/include/python -I../library $(CCOPT)

LIBDIR ?= /usr/lib64
MANDIR ?= /usr/share/man
PYDIR  := $(shell readlink -f $(LIBDIR)/python/site-packages)

OBJS	= extension.o \
	  command.o \
	  transfer.o \
	  status.o \
	  target.o

all: twopence.so

twopence.so: $(OBJS)
	$(CC) --shared -o $@ $(OBJS) -L../library -ltwopence

clean:
	rm -f *.o *.so

install:
	mkdir -p $(DESTDIR)$(PYDIR)
	cp twopence.so $(DESTDIR)$(PYDIR)
	mkdir -p $(DESTDIR)$(MANDIR)/man3
	gzip -c twopence.3py > $(DESTDIR)$(MANDIR)/man3/twopence.3py.gz
