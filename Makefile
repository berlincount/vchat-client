#
# vchat-client - alpha version
#

##############################################
# configuration                              #
##############################################

CFLAGS = -Wall -Os #-g -ggdb

## use this line when you've got an readline before 4.(x|2)
CFLAGS += -DOLDREADLINE

## you might need one or more of these:
#CFLAGS += -I/usr/local/ssl/include -L/usr/local/ssl/lib
#CFLAGS += -I/usr/local/include -L/usr/local/lib
#CFLAGS += -I/usr/pkg/include -L/usr/pkg/lib

## enable dietlibc
#CC = diet cc
#CFLAGS += -static

## enable debug code
#CFLAGS += -DDEBUG

## the install prefix best is /usr/local
PREFIX=/usr/local

LIBS   = -lncurses -lreadline -lssl -lcrypto
OBJS   = vchat-client.o vchat-ui.o vchat-protocol.o vchat-user.o vchat-commands.o


##############################################
# general targets                            #
##############################################


all: vchat-client #vchat-client.1

install: vchat-client vchat-keygen vchatrc.ex
	install -d $(DESTDIR)/etc
	install -d $(DESTDIR)$(PREFIX)/bin
	install -d $(DESTDIR)$(PREFIX)/share/man/man1
	install -m 0755 ./vchat-client $(DESTDIR)$(PREFIX)/bin
	install -m 0755 ./vchat-keygen $(DESTDIR)$(PREFIX)/bin
#	install -m 0644 ./vchat-client.1 $(DESTDIR)$(PREFIX)/share/man/man1
	install -m 0644 ./vchatrc.ex $(DESTDIR)/etc/vchatrc


uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/vchat-client
	rm -f $(DESTDIR)$(PREFIX)/bin/vchat-keygen
	rm -f $(DESTDIR)$(PREFIX)/share/man/man1/vchat-client.1
	rm -f $(DESTDIR)/etc/vchatrc


clean:
	rm -f .\#* debian/*~ *~ .*~ *.o vchat-client core *.strace \
	*.ltrace vchat.err vchat.debug* vchat-client.1 manpage.*


##############################################
# compile targets                            #
##############################################

vchat-client: $(OBJS)
	$(CC) $(CFLAGS) -o vchat-client $(OBJS) $(LIBS)

vchat-client.o: vchat-client.c vchat-config.h Makefile
	$(CC) $(CFLAGS) -o vchat-client.o -c vchat-client.c

vchat-ui.o: vchat-ui.c vchat.h
	$(CC) $(CFLAGS) -o vchat-ui.o -c vchat-ui.c

vchat-protocol.o: vchat-protocol.c vchat-messages.h vchat.h Makefile
	$(CC) $(CFLAGS) -o vchat-protocol.o -c vchat-protocol.c

vchat-user.o: vchat-user.c vchat.h
	$(CC) $(CFLAGS) -o vchat-user.o -c vchat-user.c

vchat-commands.o: vchat-commands.c vchat.h vchat-config.h
	$(CC) $(CFLAGS) -o vchat-commands.o -c vchat-commands.c

#vchat-client.1: vchat-client.sgml
#	docbook2man vchat-client.sgml
