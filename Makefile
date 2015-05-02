SRC = btun.c
OBJ = index.o script.o
LIBS = -lwebsockets -lev
PREFIX ?= /usr/local
MANPREFIX ?= $(PREFIX)/share/man
VERSION = $(shell head -n 1 README.md | cut -d- -f 2)

all: btun

btun: $(SRC) $(OBJ)
	$(CC) -DVERSION=\"$(VERSION)\" -o $@ $(LIBS) $(CFLAGS) $(LDFLAGS) $(SRC) $(OBJ)

install: btun
	mkdir -p $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(MANPREFIX)/man1
	cp -f btun $(DESTDIR)$(PREFIX)/bin
	chmod 755 $(DESTDIR)$(PREFIX)/bin/btun
	cp -f btun.1 $(DESTDIR)$(MANPREFIX)/man1/
	chmod 644 $(DESTDIR)$(MANPREFIX)/man1/btun.1

index.o: index.html
	$(LD) $(LDFLAGS) -r -b binary -o $@ $<

script.o: script.js
	$(LD) $(LDFLAGS) -r -b binary -o $@ $<

clean:
	rm -f *.o btun

btun.1: README.md
	pandoc -f markdown_github -t man $< | \
		sed "1s/\.SH/.TH/" > $@

.PHONY: clean install
