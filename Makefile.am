
SUBDIRS = . doc

AM_MAKEFLAGS = --no-print-directory

pkginclude_HEADERS = ell/ell.h ell/util.h \
				ell/test.h \
				ell/queue.h \
				ell/hashmap.h \
				ell/string.h \
				ell/main.h \
				ell/signal.h \
				ell/timeout.h \
				ell/io.h \
				ell/plugin.h \
				ell/checksum.h

lib_LTLIBRARIES = ell/libell.la

ell_libell_la_SOURCES = $(include_HEADERS) ell/private.h \
						ell/util.c \
						ell/test.c \
						ell/queue.c \
						ell/hashmap.c \
						ell/string.c \
						ell/main.c \
						ell/signal.c \
						ell/timeout.c \
						ell/io.c \
						ell/plugin.c \
						ell/checksum.c

ell_libell_la_LDFLAGS = -version-info 0:0:0

noinst_LTLIBRARIES = ell/libell-private.la

ell_libell_private_la_SOURCES = $(ell_libell_la_SOURCES)

AM_CFLAGS = -fvisibility=hidden

pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = ell/ell.pc

noinst_PROGRAMS = unit/test-unit unit/test-queue \
				unit/test-hashmap unit/test-string \
				unit/test-main unit/test-io unit/test-checksum

unit_test_unit_LDADD = ell/libell-private.la

unit_test_queue_LDADD = ell/libell-private.la

unit_test_hashmap_LDADD = ell/libell-private.la

unit_test_string_LDADD = ell/libell-private.la

unit_test_main_LDADD = ell/libell-private.la

unit_test_io_LDADD = ell/libell-private.la

unit_test_checksum_LDADD = ell/libell-private.la

TESTS = $(noinst_PROGRAMS)

DISTCHECK_CONFIGURE_FLAGS = --disable-gtk-doc

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh mkinstalldirs
