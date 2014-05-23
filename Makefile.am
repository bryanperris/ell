
AM_MAKEFLAGS = --no-print-directory

ACLOCAL_AMFLAGS = -I build-aux

# Library code modified:	REVISION++
# Interfaces changed:		CURRENT++ REVISION=0
# Interfaces added:		CURRENT++ REVISION=0 AGE++
# Interfaces removed:		CURRENT++ REVISION=0 AGE=0

ELL_CURRENT = 0
ELL_REVISION = 0
ELL_AGE = 0

linux_headers = linux/kdbus.h

pkginclude_HEADERS = ell/ell.h \
			ell/util.h \
			ell/test.h \
			ell/queue.h \
			ell/hashmap.h \
			ell/string.h \
			ell/settings.h \
			ell/main.h \
			ell/idle.h \
			ell/signal.h \
			ell/timeout.h \
			ell/io.h \
			ell/log.h \
			ell/plugin.h \
			ell/checksum.h \
			ell/netlink.h \
			ell/dbus.h \
			ell/dbus-service.h

lib_LTLIBRARIES = ell/libell.la

ell_libell_la_SOURCES = $(linux_headers) \
			$(pkginclude_HEADERS) \
			ell/private.h \
			ell/util.c \
			ell/test.c \
			ell/queue.c \
			ell/hashmap.c \
			ell/string.c \
			ell/settings.c \
			ell/main.c \
			ell/idle.c \
			ell/signal.c \
			ell/timeout.c \
			ell/io.c \
			ell/log.c \
			ell/plugin.c \
			ell/checksum.c \
			ell/netlink.c \
			ell/dbus-private.h \
			ell/dbus.c \
			ell/dbus-kernel.c \
			ell/dbus-message.c \
			ell/dbus-util.c \
			ell/dbus-service.c \
			ell/gvariant-private.h \
			ell/gvariant-util.c

ell_libell_la_LDFLAGS = -no-undefined \
			-version-info $(ELL_CURRENT):$(ELL_REVISION):$(ELL_AGE)

noinst_LTLIBRARIES = ell/libell-private.la

ell_libell_private_la_SOURCES = $(ell_libell_la_SOURCES)

AM_CFLAGS = -fvisibility=hidden -DTESTDATADIR=\""$(top_srcdir)/unit"\"

pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = ell/ell.pc

noinst_PROGRAMS =

unit_tests = unit/test-unit \
			unit/test-queue \
			unit/test-hashmap \
			unit/test-string \
			unit/test-utf8 \
			unit/test-main \
			unit/test-io \
			unit/test-plugin \
			unit/test-checksum \
			unit/test-settings \
			unit/test-netlink \
			unit/test-kdbus \
			unit/test-dbus \
			unit/test-dbus-util \
			unit/test-dbus-message \
			unit/test-dbus-service \
			unit/test-gvariant-util \
			unit/test-gvariant-message

if MAINTAINER_MODE
noinst_PROGRAMS += $(unit_tests)
endif

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

unit_test_kdbus_LDADD = ell/libell-private.la

unit_test_dbus_LDADD = ell/libell-private.la

unit_test_dbus_message_LDADD = ell/libell-private.la

unit_test_dbus_util_LDADD = ell/libell-private.la

unit_test_dbus_service_LDADD = ell/libell-private.la

unit_test_gvariant_util_LDADD = ell/libell-private.la

unit_test_gvariant_message_LDADD = ell/libell-private.la

if MAINTAINER_MODE
noinst_LTLIBRARIES += unit/example-plugin.la
endif

unit_example_plugin_la_LDFLAGS = -no-undefined -module -avoid-version \
							-rpath /dummy

unit_test_data_files = unit/settings.test

EXTRA_DIST = $(unit_test_data_files)

TESTS = $(unit_tests)

DISTCLEANFILES = $(unit_tests)

MAINTAINERCLEANFILES = Makefile.in configure config.h.in aclocal.m4

maintainer-clean-local:
	-rm -rf build-aux
