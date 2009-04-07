# Debugging and gcc warning flags
CFLAGS = -g -Wall
# Optimization
# CFLAGS = -O6

# Where you want stuff installed
# PREFIX = /usr/local

# For systems that need it
# LDLIBS = -lsocket -lnsl

# If you want to build the Ethereal plugin ("make ethereal")
ETHEREAL_INCLUDES = -I/usr/include/ethereal `glib-config --cflags`
ETHEREAL_DIR = $(HOME)/.ethereal/plugins

##############################################################################

all: airtest aircat airproxy looptest

airtest: airtest.o libairhook.a
airtest.o: airtest.c airhook.h airhook-internal.h

aircat: aircat.o libairhook.a
aircat.o: aircat.c airhook.h airhook-internal.h

airproxy: airproxy.o libairhook.a
airproxy.o: airproxy.c airhook.h airhook-internal.h

looptest: looptest.o

packet.o: packet.c airhook.h airhook-private.h
protocol.o: protocol.c airhook.h airhook-internal.h airhook-private.h

libairhook.a: packet.o protocol.o
	$(AR) ru $@ $^

clean:
	$(RM) -r libairhook.a *.o *.lo *.la airtest aircat airproxy looptest .libs

install: all
	@test -n '$(PREFIX)' || \
	( echo 'usage: make install PREFIX=/your/prefix' ; exit 1 )
	mkdir -p '$(PREFIX)/bin' '$(PREFIX)/lib' '$(PREFIX)/include'
	cp libairhook.a '$(PREFIX)/lib'
	cp airhook.h airhook-internal.h '$(PREFIX)/include'
	cp aircat airproxy '$(PREFIX)/bin'

tar:
	rm -f airhook-2
	ln -s . airhook-2
	tar cf airhook-2.tar \
		airhook-2/README airhook-2/COPYING airhook-2/Makefile \
		airhook-2/*.c airhook-2/*.h
	rm -f airhook-2.tar.gz
	gzip airhook-2.tar

##############################################################################

ethereal: airhook.la airproxy.la
install-ethereal: $(ETHEREAL_DIR)/airhook.la $(ETHEREAL_DIR)/airproxy.la

airhook.la: packet-airhook.lo packet.lo
airproxy.la: packet-airproxy.lo

packet-airhook.lo: packet-airhook.c airhook.h airhook-private.h
packet-airproxy.lo: packet-airproxy.c airhook.h airhook-private.h
packet.lo: packet.c airhook.h airhook-private.h

%.lo: %.c
	libtool $(CC) $(CPPFLAGS) $(ETHEREAL_INCLUDES) -c $*.c -o $@

%.la: packet-%.lo
	libtool $(CC) -module -avoid-version -rpath $(ETHEREAL_DIR) $^ -o $@

$(ETHEREAL_DIR)/%.la: %.la
	mkdir -p $(ETHEREAL_DIR)
	libtool cp $^ $@
