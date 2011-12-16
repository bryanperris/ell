
AM_MAKEFLAGS = --no-print-directory

pkginclude_HEADERS = ell/ell.h ell/util.h \
				ell/queue.h \
				ell/hashmap.h

lib_LTLIBRARIES = ell/libell.la

ell_libell_la_SOURCES = $(include_HEADERS) ell/private.h \
						ell/queue.c \
						ell/hashmap.c

ell_libell_la_LDFLAGS = -version-info 0:0:0

noinst_LTLIBRARIES = ell/libell-private.la

ell_libell_private_la_SOURCES = $(ell_libell_la_SOURCES)

AM_CFLAGS = -fvisibility=hidden

pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = ell/ell.pc

noinst_PROGRAMS = unit/test-hashmap

unit_test_hashmap_LDADD = ell/libell-private.la

TESTS = $(noinst_PROGRAMS)

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh mkinstalldirs
