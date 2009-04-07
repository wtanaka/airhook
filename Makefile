# Debugging and gcc warning flags
CFLAGS = -g -Wall
# Optimization
# CFLAGS = -O6

# Where you want stuff installed
# PREFIX = /usr/local

# For systems that need it
# LDLIBS = -lsocket -lnsl

##############################################################################

all: airtest aircat airproxy

airtest: airtest.o libairhook.a
airtest.o: airtest.c airhook.h airhook-internal.h

aircat: aircat.o libairhook.a
aircat.o: aircat.c airhook.h airhook-internal.h

airproxy: airproxy.o libairhook.a
airproxy.o: airproxy.c airhook.h airhook-internal.h

libairhook.a: packet.o protocol.o
	$(AR) ru $@ $^

packet.o: packet.c airhook-private.h
protocol.o: protocol.c airhook.h airhook-internal.h airhook-private.h

clean:
	$(RM) libairhook.a *.o airtest aircat airproxy

install: all
	@test -n '$(PREFIX)' || \
	( echo 'usage: make install PREFIX=/your/prefix' ; exit 1 )
	mkdir -p '$(PREFIX)/bin' '$(PREFIX)/lib' '$(PREFIX)/include'
	cp libairhook.a '$(PREFIX)/lib'
	cp airhook.h airhook-internal.h '$(PREFIX)/include'
	cp aircat airproxy '$(PREFIX)/bin'

tar:
	rm -f airhook-1
	ln -s . airhook-1
	tar cf airhook-1.tar \
		airhook-1/README airhook-1/COPYING airhook-1/Makefile \
		airhook-1/*.c airhook-1/*.h
	rm -f airhook-1.tar.gz
	gzip airhook-1.tar
