# *BSD-specific makefile parts

OSNAME != uname

ifdef MANPAGE
all: vchat-client vchat-client.1

vchat-client.1: vchat-client.sgml
	docbook2man vchat-client.sgml

install-manpage: vchat-client.1
	install -d $(DESTDIR)$(PREFIX)/share/man/man1
	install -m 0644 ./vchat-client.1 $(DESTDIR)$(PREFIX)/share/man/man1

MANTARGET=install-manpage
else
all: vchat-client

MANTARGET=
endif

## RELRO + immediate-bind is Linux/glibc-specific; harmless on others
## that ignore unknown -z options, but Apple ld will warn.
ifneq ($(OSNAME),Darwin)
LDFLAGS += -Wl,-z,relro,-z,now
endif

include Makefile.common
