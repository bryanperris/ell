
SUBDIRS = . doc

AM_MAKEFLAGS = --no-print-directory

pkginclude_HEADERS = ell/ell.h ell/util.h \
				ell/test.h \
				ell/queue.h \
				ell/hashmap.h \
				ell/string.h \
				ell/settings.h \
				ell/main.h \
				ell/signal.h \
				ell/timeout.h \
				ell/io.h \
				ell/log.h \
				ell/plugin.h \
				ell/checksum.h \
				ell/netlink.h \
				ell/dbus.h

lib_LTLIBRARIES = ell/libell.la

ell_libell_la_SOURCES = $(include_HEADERS) ell/private.h \
						ell/util.c \
						ell/test.c \
						ell/queue.c \
						ell/hashmap.c \
						ell/string.c \
						ell/settings.c \
						ell/main.c \
						ell/signal.c \
						ell/timeout.c \
						ell/io.c \
						ell/log.c \
						ell/plugin.c \
						ell/checksum.c \
						ell/netlink.c \
						ell/dbus.c

ell_libell_la_LDFLAGS = -version-info 0:0:0

noinst_LTLIBRARIES = ell/libell-private.la

ell_libell_private_la_SOURCES = $(ell_libell_la_SOURCES)

AM_CFLAGS = -fvisibility=hidden

pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = ell/ell.pc

noinst_PROGRAMS = unit/test-unit unit/test-queue \
				unit/test-hashmap unit/test-string \
				unit/test-utf8 \
				unit/test-main unit/test-io \
				unit/test-plugin unit/test-checksum \
				unit/test-settings \
				unit/test-netlink unit/test-dbus

unit_test_unit_LDADD = ell/libell-private.la

unit_test_queue_LDADD = ell/libell-private.la

unit_test_hashmap_LDADD = ell/libell-private.la

unit_test_string_LDADD = ell/libell-private.la

unit_test_utf8_LDADD = ell/libell-private.la

unit_test_main_LDADD = ell/libell-private.la

unit_test_io_LDADD = ell/libell-private.la

unit_test_plugin_LDADD = ell/libell-private.la -ldl

unit_test_checksum_LDADD = ell/libell-private.la

unit_test_settings_LDADD = ell/libell-private.la

unit_test_netlink_LDADD = ell/libell-private.la

unit_test_dbus_LDADD = ell/libell-private.la

noinst_LTLIBRARIES += unit/example-plugin.la

unit_example_plugin_la_LDFLAGS = -no-undefined -module -avoid-version \
							-rpath /dummy

TESTS = $(noinst_PROGRAMS)

DISTCHECK_CONFIGURE_FLAGS = --disable-gtk-doc

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh mkinstalldirs
