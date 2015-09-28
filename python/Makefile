
ifdef RPM_OPT_FLAGS
CCOPT	= $(RPM_OPT_FLAGS)
else
CCOPT	= -Wall -O2 -g
endif

CFLAGS	= -fPIC -I/usr/include/python -I../library $(CCOPT)

LIBDIR ?= /usr/lib64
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
	../instman.sh -z -d "$(DESTDIR)" twopence.3py
