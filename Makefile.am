
AM_MAKEFLAGS = --no-print-directory

pkginclude_HEADERS = ell/ell.h

lib_LTLIBRARIES = ell/libell.la

ell_libell_la_SOURCES = $(include_HEADERS) ell/util.h

ell_libell_la_LDFLAGS = -version-info 0:0:0

noinst_LTLIBRARIES = ell/libell-private.la

ell_libell_private_la_SOURCES = $(ell_libell_la_SOURCES)

AM_CFLAGS = -fvisibility=hidden

pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = ell/ell.pc

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh mkinstalldirs
