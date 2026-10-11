CC ?= gcc
AR ?= ar
CFLAGS ?= -O3 -Wall -Wextra -pedantic -std=c99 -fPIC
CPPFLAGS ?= -Iinclude
PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include
PKGCONFIGDIR ?= $(LIBDIR)/pkgconfig

VERSION = 1.4.1
MAJOR = 1

STATIC_LIB = libbogons.a
SHARED_LIB = libbogons.so
SHARED_LIB_VERSIONED = $(SHARED_LIB).$(VERSION)
SHARED_LIB_SONAME = $(SHARED_LIB).$(MAJOR)

all: $(STATIC_LIB) $(SHARED_LIB) test

src/bogons.o: src/bogons.c include/bogons.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c src/bogons.c -o src/bogons.o

$(STATIC_LIB): src/bogons.o
	$(AR) rcs $@ $^

$(SHARED_LIB): src/bogons.o
	$(CC) -shared -Wl,-soname,$(SHARED_LIB_SONAME) -o $(SHARED_LIB_VERSIONED) src/bogons.o
	ln -sf $(SHARED_LIB_VERSIONED) $(SHARED_LIB_SONAME)
	ln -sf $(SHARED_LIB_SONAME) $(SHARED_LIB)

tests/test_bogons.o: tests/test_bogons.c include/bogons.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tests/test_bogons.c -o tests/test_bogons.o

test: tests/test_bogons.o $(STATIC_LIB)
	$(CC) $(CFLAGS) $(CPPFLAGS) tests/test_bogons.o $(STATIC_LIB) -o tests/test_bogons
	./tests/test_bogons

bogons.pc:
	@echo "prefix=$(PREFIX)" > bogons.pc
	@echo "exec_prefix=\$${prefix}" >> bogons.pc
	@echo "libdir=$(LIBDIR)" >> bogons.pc
	@echo "includedir=$(INCLUDEDIR)" >> bogons.pc
	@echo "" >> bogons.pc
	@echo "Name: bogons" >> bogons.pc
	@echo "Description: Lean, high-performance IP and ASN bogon validation library" >> bogons.pc
	@echo "Version: $(VERSION)" >> bogons.pc
	@echo "Libs: -L\$${libdir} -lbogons" >> bogons.pc
	@echo "Cflags: -I\$${includedir}" >> bogons.pc

install: $(STATIC_LIB) $(SHARED_LIB) bogons.pc
	install -d $(DESTDIR)$(INCLUDEDIR)
	install -m 644 include/bogons.h $(DESTDIR)$(INCLUDEDIR)/
	install -d $(DESTDIR)$(LIBDIR)
	install -m 644 $(STATIC_LIB) $(DESTDIR)$(LIBDIR)/
	install -m 755 $(SHARED_LIB_VERSIONED) $(DESTDIR)$(LIBDIR)/
	ln -sf $(SHARED_LIB_VERSIONED) $(DESTDIR)$(LIBDIR)/$(SHARED_LIB_SONAME)
	ln -sf $(SHARED_LIB_SONAME) $(DESTDIR)$(LIBDIR)/$(SHARED_LIB)
	install -d $(DESTDIR)$(PKGCONFIGDIR)
	install -m 644 bogons.pc $(DESTDIR)$(PKGCONFIGDIR)/

clean:
	rm -f src/*.o tests/*.o tests/test_bogons $(STATIC_LIB) $(SHARED_LIB)* bogons.pc

.PHONY: all test clean install
