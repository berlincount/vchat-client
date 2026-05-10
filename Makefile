#
# vchat-client - beta version
#

##############################################
# configuration                              #
##############################################

OBJS = vchat-client.o vchat-ui.o vchat-protocol.o vchat-user.o vchat-commands.o vchat-tls.o vchat-connection.o

# On FreeBSD you might want to link -ncursesw
#LIBS = -lncurses
LIBS = -lncursesw

LIBS += -lreadline

CFLAGS += -Wall -Os
CFLAGS += -I/usr/local/include
LDFLAGS += -L/usr/local/lib

## Default hardening for a network-facing client.  Cheap to enable,
## near-zero source impact, catch & contain a useful subset of memory
## corruption and format-string mistakes.  Comment out individual lines
## if your toolchain doesn't support them.
CFLAGS += -D_FORTIFY_SOURCE=2
CFLAGS += -fstack-protector-strong
CFLAGS += -Wformat -Wformat-security
## RELRO + immediate-bind is Linux/glibc-specific; harmless on others
## that ignore unknown -z options, but Apple ld will warn.
ifneq ($(shell uname),Darwin)
LDFLAGS += -Wl,-z,relro,-z,now
endif

## use this line when you've got an readline before 4.(x|2)
#CFLAGS += -DOLDREADLINE

# Alternatively, you can just build with make OLDREADLINE=-DOLDREADLINE
# if you can't modify this Makefile
CFLAGS += $(OLDREADLINE)

##### Enable this for enabling the OpenSSL library
CFLAGS += -DTLS_LIB_OPENSSL
LIBS += -lssl -lcrypto

##### Enable this for enabling the mbedTLS library
#CFLAGS += -DTLS_LIB_MBEDTLS
#LIBS += -lmbedx509 -lmbedtls -lmbedcrypto

## you might need one or more of these:
#CFLAGS+= -Wextra -Wall -g -ggdb
#CFLAGS+= -arch x86_64 -Wno-deprecated-declarations
#CFLAGS+= -arch i386 -Wno-deprecated-declarations
#CFLAGS += -I/usr/local/ssl/include -L/usr/local/ssl/lib
#CFLAGS += -I/usr/pkg/include -L/usr/pkg/lib
#LDFLAGS += -L"/usr/local/opt/openssl@1.1/lib"
#CFLAGS += -I../readline-6.3
#LIBS += ../readline-6.3/libreadline.a

## enable dietlibc
#CC = diet cc
#CFLAGS += -static

## enable debug code
#CFLAGS += -DDEBUG

## the install prefix best is /usr/local
PREFIX=/usr/local


##############################################
# general targets                            #
##############################################


ifdef MANPAGE
all: vchat-client vchat-client.1
else
all: vchat-client
endif

install: vchat-client vchat-keygen vchatrc.ex
	install -d $(DESTDIR)/etc
	install -d $(DESTDIR)$(PREFIX)/bin
	install -d $(DESTDIR)$(PREFIX)/share/man/man1
	install -m 0755 ./vchat-client $(DESTDIR)$(PREFIX)/bin
	install -m 0755 ./vchat-keygen $(DESTDIR)$(PREFIX)/bin
	install -m 0644 ./vchatrc.ex $(DESTDIR)/etc/vchatrc
ifdef MANPAGE
	install -m 0644 ./vchat-client.1 $(DESTDIR)$(PREFIX)/share/man/man1
endif

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
	$(CC) $(CFLAGS) -o vchat-client $(OBJS) $(LIBS) $(LDFLAGS)

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

vchat-tls.o: vchat-tls.c vchat-tls.h
	$(CC) $(CFLAGS) -o vchat-tls.o -c vchat-tls.c

vchat-connection.o: vchat-connection.c vchat-connection.h
	$(CC) $(CFLAGS) -o vchat-connection.o -c vchat-connection.c

ifdef MANPAGE
vchat-client.1: vchat-client.sgml
	docbook2man vchat-client.sgml
endif
