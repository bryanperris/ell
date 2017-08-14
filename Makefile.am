
AM_MAKEFLAGS = --no-print-directory

ACLOCAL_AMFLAGS = -I build-aux

# Library code modified:	REVISION++
# Interfaces changed:		CURRENT++ REVISION=0
# Interfaces added:		CURRENT++ REVISION=0 AGE++
# Interfaces removed:		CURRENT++ REVISION=0 AGE=0

ELL_CURRENT = 0
ELL_REVISION = 1
ELL_AGE = 0

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
			ell/ringbuf.h \
			ell/log.h \
			ell/plugin.h \
			ell/checksum.h \
			ell/netlink.h \
			ell/genl.h \
			ell/dbus.h \
			ell/dbus-service.h \
			ell/hwdb.h \
			ell/cipher.h \
			ell/random.h \
			ell/uintset.h \
			ell/base64.h \
			ell/pem.h \
			ell/tls.h \
			ell/uuid.h \
			ell/key.h

lib_LTLIBRARIES = ell/libell.la

ell_libell_la_SOURCES = $(linux_headers) \
			$(pkginclude_HEADERS) \
			ell/private.h \
			ell/missing.h \
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
			ell/ringbuf.c \
			ell/log.c \
			ell/plugin.c \
			ell/checksum.c \
			ell/netlink-private.h \
			ell/netlink.c \
			ell/genl-private.h \
			ell/genl.c \
			ell/dbus-private.h \
			ell/dbus.c \
			ell/dbus-message.c \
			ell/dbus-util.c \
			ell/dbus-service.c \
			ell/dbus-name-cache.c \
			ell/dbus-filter.c \
			ell/gvariant-private.h \
			ell/gvariant-util.c \
			ell/siphash-private.h \
			ell/siphash.c \
			ell/hwdb.c \
			ell/cipher.c \
			ell/random.c \
			ell/uintset.c \
			ell/base64.c \
			ell/asn1-private.h \
			ell/pem.c \
			ell/tls-private.h \
			ell/tls.c \
			ell/tls-record.c \
			ell/uuid.c \
			ell/key.c

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
			unit/test-endian \
			unit/test-string \
			unit/test-utf8 \
			unit/test-main \
			unit/test-io \
			unit/test-ringbuf \
			unit/test-plugin \
			unit/test-checksum \
			unit/test-settings \
			unit/test-netlink \
			unit/test-genl \
			unit/test-genl-msg \
			unit/test-siphash \
			unit/test-cipher \
			unit/test-random \
			unit/test-util \
			unit/test-uintset \
			unit/test-base64 \
			unit/test-pem \
			unit/test-uuid

dbus_tests = unit/test-hwdb \
			unit/test-dbus \
			unit/test-dbus-util \
			unit/test-dbus-message \
			unit/test-dbus-message-fds \
			unit/test-dbus-service \
			unit/test-dbus-watch \
			unit/test-dbus-properties \
			unit/test-gvariant-util \
			unit/test-gvariant-message

tls_tests = unit/test-tls \
			unit/test-key

if MAINTAINER_MODE
noinst_PROGRAMS += $(unit_tests) $(dbus_tests) $(tls_tests)
endif

unit_test_unit_LDADD = ell/libell-private.la

unit_test_queue_LDADD = ell/libell-private.la

unit_test_hashmap_LDADD = ell/libell-private.la

unit_test_endian_LDADD = ell/libell-private.la

unit_test_string_LDADD = ell/libell-private.la

unit_test_utf8_LDADD = ell/libell-private.la

unit_test_main_LDADD = ell/libell-private.la

unit_test_io_LDADD = ell/libell-private.la

unit_test_ringbuf_LDADD = ell/libell-private.la

unit_test_plugin_LDADD = ell/libell-private.la -ldl

unit_test_checksum_LDADD = ell/libell-private.la

unit_test_settings_LDADD = ell/libell-private.la

unit_test_netlink_LDADD = ell/libell-private.la

unit_test_genl_LDADD = ell/libell-private.la

unit_test_genl_msg_LDADD = ell/libell-private.la

unit_test_dbus_LDADD = ell/libell-private.la

unit_test_dbus_message_LDADD = ell/libell-private.la

unit_test_dbus_message_fds_LDADD = ell/libell-private.la

unit_test_dbus_util_LDADD = ell/libell-private.la

unit_test_dbus_service_LDADD = ell/libell-private.la

unit_test_dbus_watch_LDADD = ell/libell-private.la

unit_test_dbus_properties_LDADD = ell/libell-private.la

unit_test_gvariant_util_LDADD = ell/libell-private.la

unit_test_gvariant_message_LDADD = ell/libell-private.la

unit_test_siphash_LDADD = ell/libell-private.la

unit_test_hwdb_LDADD = ell/libell-private.la

unit_test_cipher_LDADD = ell/libell-private.la

unit_test_random_LDADD = ell/libell-private.la

unit_test_util_LDADD = ell/libell-private.la

unit_test_uintset_LDADD = ell/libell-private.la

unit_test_pem_LDADD = ell/libell-private.la

unit_test_base64_LDADD = ell/libell-private.la

unit_test_tls_LDADD = ell/libell-private.la

unit_test_uuid_LDADD = ell/libell-private.la

unit_test_key_LDADD = ell/libell-private.la

if MAINTAINER_MODE
noinst_LTLIBRARIES += unit/example-plugin.la
endif

unit_example_plugin_la_LDFLAGS = -no-undefined -module -avoid-version \
							-rpath /dummy

unit_test_data_files = unit/settings.test unit/cert-ca.pem \
			unit/cert-client.pem unit/cert-server.pem \
			unit/cert-client-key.pem unit/cert-server-key.pem \
			unit/cert-intca.pem unit/cert-entity-int.pem \
			unit/cert-client-key-pkcs8.pem \
			unit/cert-server-key-pkcs8.pem \
			unit/dbus.conf

examples = examples/dbus-service examples/https-client-test \
		examples/https-server-test examples/dbus-client

if MAINTAINER_MODE
noinst_PROGRAMS += $(examples)
endif

examples_dbus_service_LDADD = ell/libell-private.la
examples_https_client_test_LDADD = ell/libell-private.la
examples_https_server_test_LDADD = ell/libell-private.la
examples_dbus_client_LDADD = ell/libell-private.la

EXTRA_DIST = $(unit_test_data_files)

TESTS = $(unit_tests)

if DBUS_TESTS
TESTS += $(dbus_tests)
endif

if TLS_TESTS
TESTS += $(tls_tests)
endif

DISTCLEANFILES = $(unit_tests) $(dbus_tests) $(tls_tests)

MAINTAINERCLEANFILES = Makefile.in configure config.h.in aclocal.m4

maintainer-clean-local:
	-rm -rf build-aux
