
ifdef RPM_OPT_FLAGS
CCOPT	= $(RPM_OPT_FLAGS)
else
CCOPT	= -Wall -O2 -g
endif

CFLAGS	= -fPIC -I/usr/include/python -I/usr/include/python2.7 
CFLAGS  += -I../library $(CCOPT)

LIBDIR ?= /usr/lib64
# if /usr/lib64/python exists then use readlink (openSUSE)
ifeq ($(wildcard $(LIBDIR)/python/),)
    #fedora, ubuntu
    PYDIR := $(LIBDIR)/python2.7/site-packages/
else
    PYDIR := $(shell readlink -f $(LIBDIR)/python/site-packages)
endif

OBJS	= extension.o \
	  command.o \
	  transfer.o \
	  status.o \
	  chat.o \
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
