
AM_MAKEFLAGS = --no-print-directory

ACLOCAL_AMFLAGS = -I build-aux

# Library code modified:	REVISION++
# Interfaces changed:		CURRENT++ REVISION=0
# Interfaces added:		CURRENT++ REVISION=0 AGE++
# Interfaces removed:		CURRENT++ REVISION=0 AGE=0

ELL_CURRENT = 0
ELL_REVISION = 2
ELL_AGE = 0

pkginclude_HEADERS = ell/ell.h \
			ell/util.h \
			ell/test.h \
			ell/strv.h \
			ell/utf8.h \
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
			ell/dbus-client.h \
			ell/hwdb.h \
			ell/cipher.h \
			ell/random.h \
			ell/uintset.h \
			ell/base64.h \
			ell/pem.h \
			ell/tls.h \
			ell/uuid.h \
			ell/key.h \
			ell/pkcs5.h \
			ell/file.h \
			ell/dir.h \
			ell/net.h \
			ell/dhcp.h \
			ell/cert.h \
			ell/ecc.h \
			ell/ecdh.h \
			ell/time.h

lib_LTLIBRARIES = ell/libell.la

ell_libell_la_SOURCES = $(linux_headers) \
			$(pkginclude_HEADERS) \
			ell/private.h \
			ell/missing.h \
			ell/util.c \
			ell/test.c \
			ell/strv.c \
			ell/utf8.c \
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
			ell/dbus-client.c \
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
			ell/tls-extensions.c \
			ell/tls-suites.c \
			ell/uuid.c \
			ell/key.c \
			ell/pkcs5-private.h \
			ell/pkcs5.c \
			ell/file.c \
			ell/dir.c \
			ell/net.c \
			ell/dhcp-private.h \
			ell/dhcp.c \
			ell/dhcp-transport.c \
			ell/dhcp-lease.c \
			ell/cert.c \
			ell/cert-private.h \
			ell/ecc-private.h \
			ell/ecc.h \
			ell/ecc-external.c \
			ell/ecc.c \
			ell/ecdh.c \
			ell/time.c

ell_libell_la_LDFLAGS = -no-undefined \
			-Wl,--version-script=$(top_srcdir)/ell/ell.sym \
			-version-info $(ELL_CURRENT):$(ELL_REVISION):$(ELL_AGE)

ell_libell_la_DEPENDENCIES = ell/ell.sym

noinst_LTLIBRARIES = ell/libell-private.la

ell_libell_private_la_SOURCES = $(ell_libell_la_SOURCES)

AM_CFLAGS = -fvisibility=hidden -DUNITDIR=\""$(top_srcdir)/unit/"\" \
				-DCERTDIR=\""$(top_builddir)/unit/"\"

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
			unit/test-uuid \
			unit/test-pbkdf2 \
			unit/test-dhcp \
			unit/test-dir-watch \
			unit/test-ecc \
			unit/test-ecdh \
			unit/test-time

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

cert_tests = unit/test-pem \
			unit/test-tls \
			unit/test-key

cert_files = unit/cert-chain.pem \
			unit/cert-entity-int.pem \
			unit/cert-server.pem \
			unit/cert-client.pem \
			unit/cert-server-key-pkcs8.pem \
			unit/cert-client-key-pkcs8.pem \
			unit/cert-client-key-md5-des.pem \
			unit/cert-client-key-sha1-des.pem \
			unit/cert-client-key-v2-des.pem \
			unit/cert-client-key-v2-des-ede3.pem \
			unit/cert-client-key-v2-aes128.pem \
			unit/cert-client-key-v2-aes256.pem

cert_checks = unit/cert-intca \
			unit/cert-entity-int \
			unit/cert-server \
			unit/cert-client

if MAINTAINER_MODE
noinst_PROGRAMS += $(unit_tests) $(dbus_tests) $(cert_tests)
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

unit_test_plugin_LDFLAGS = -Wl,-export-dynamic
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

unit_test_base64_LDADD = ell/libell-private.la

unit_test_pbkdf2_LDADD = ell/libell-private.la

unit_test_pem_LDADD = ell/libell-private.la
unit_test_pem_DEPENDENCIES = $(cert_files) ell/libell-private.la

unit_test_tls_LDADD = ell/libell-private.la
unit_test_tls_DEPENDENCIES = $(cert_files) ell/libell-private.la

unit_test_key_LDADD = ell/libell-private.la
unit_test_key_DEPENDENCIES = $(cert_files) ell/libell-private.la

unit_test_uuid_LDADD = ell/libell-private.la

unit_test_dhcp_LDADD = ell/libell-private.la

unit_test_dir_watch_LDADD = ell/libell-private.la

unit_test_ecc_LDADD = ell/libell-private.la

unit_test_ecdh_LDADD = ell/libell-private.la
unit_test_ecdh_LDFLAGS = -Wl,-wrap,l_getrandom

unit_test_time_LDADD = ell/libell-private.la

if MAINTAINER_MODE
noinst_LTLIBRARIES += unit/example-plugin.la
endif

unit_example_plugin_la_LDFLAGS = -no-undefined -module -avoid-version \
							-rpath /dummy

unit_test_data_files = unit/settings.test unit/dbus.conf

examples = examples/dbus-service examples/https-client-test \
		examples/https-server-test examples/dbus-client \
		examples/dhcp-client

if GLIB
examples += examples/glib-eventloop
endif

if MAINTAINER_MODE
noinst_PROGRAMS += $(examples)
endif

examples_dbus_service_LDADD = ell/libell-private.la
examples_https_client_test_LDADD = ell/libell-private.la
examples_https_server_test_LDADD = ell/libell-private.la
examples_dbus_client_LDADD = ell/libell-private.la
examples_glib_eventloop_CFLAGS = @GLIB_CFLAGS@
examples_glib_eventloop_LDADD = ell/libell-private.la @GLIB_LIBS@
examples_dhcp_client_LDADD = ell/libell-private.la

noinst_PROGRAMS += tools/certchain-verify tools/genl-discover \
		   tools/genl-watch tools/genl-request
tools_certchain_verify_SOURCES = tools/certchain-verify.c
tools_certchain_verify_LDADD = ell/libell-private.la

tools_genl_discover_SOURCES = tools/genl-discover.c
tools_genl_discover_LDADD = ell/libell-private.la

tools_genl_watch_SOURCES = tools/genl-watch.c
tools_genl_watch_LDADD = ell/libell-private.la

tools_genl_request_SOURCES = tools/genl-request.c
tools_genl_request_LDADD = ell/libell-private.la

EXTRA_DIST = ell/ell.sym \
		$(unit_test_data_files) unit/gencerts.cnf unit/plaintext.txt

TESTS = $(unit_tests)

if DBUS_TESTS
TESTS += $(dbus_tests)
endif

if CERT_TESTS
TESTS += $(cert_tests)
endif

DISTCLEANFILES = $(unit_tests) $(dbus_tests) $(cert_tests)

MAINTAINERCLEANFILES = Makefile.in configure config.h.in aclocal.m4

true_redirect_openssl = 2>&1
false_redirect_openssl = 2>/dev/null

unit/cert-ca-key.pem:
	$(AM_V_GEN)openssl genrsa -out $@ 2048 $($(AM_V_P)_redirect_openssl)

unit/cert-ca.pem: unit/cert-ca-key.pem unit/gencerts.cnf
	$(AM_V_GEN)openssl req -x509 -new -nodes -extensions ca_ext \
			-config $(srcdir)/unit/gencerts.cnf \
			-subj '/O=International Union of Example Organizations/CN=Certificate issuer guy/emailAddress=ca@mail.example' \
			-key $< -sha256 -days 10000 -out $@

unit/cert-server-key.pem:
	$(AM_V_GEN)openssl genrsa -out $@ $($(AM_V_P)_redirect_openssl)

unit/cert-server-key-pkcs8.pem: unit/cert-server-key.pem
	$(AM_V_GEN)openssl pkcs8 -topk8 -nocrypt -in $< -out $@

unit/cert-server.csr: unit/cert-server-key.pem unit/gencerts.cnf
	$(AM_V_GEN)openssl req -new -extensions cert_ext \
			-config $(srcdir)/unit/gencerts.cnf \
			-subj '/O=Foo Example Organization/CN=Foo Example Organization/emailAddress=foo@mail.example' \
			-key $< -out $@

unit/cert-server.pem: unit/cert-server.csr unit/cert-ca.pem unit/gencerts.cnf
	$(AM_V_GEN)openssl x509 -req -extensions cert_ext \
			-extfile $(srcdir)/unit/gencerts.cnf \
			-in $< -CA $(builddir)/unit/cert-ca.pem \
			-CAkey $(builddir)/unit/cert-ca-key.pem \
			-CAserial $(builddir)/unit/cert-ca.srl \
			-CAcreateserial -sha256 -days 10000 -out $@ $($(AM_V_P)_redirect_openssl)

unit/cert-server: unit/cert-server.pem unit/cert-ca.pem
	$(AM_V_GEN)openssl verify -CAfile $(builddir)/unit/cert-ca.pem $<

unit/cert-client-key.pem:
	$(AM_V_GEN)openssl genrsa -out $@ $($(AM_V_P)_redirect_openssl)

unit/cert-client-key-pkcs8.pem: unit/cert-client-key.pem
	$(AM_V_GEN)openssl pkcs8 -topk8 -nocrypt -in $< -out $@

unit/cert-client-key-md5-des.pem: unit/cert-client-key-pkcs8.pem
	$(AM_V_GEN)openssl pkcs8 -in $< -out $@ \
			-topk8 -v1 PBE-MD5-DES -passout pass:abc

unit/cert-client-key-sha1-des.pem: unit/cert-client-key-pkcs8.pem
	$(AM_V_GEN)openssl pkcs8 -in $< -out $@ \
			-topk8 -v1 PBE-SHA1-DES -passout pass:abc

unit/cert-client-key-v2-des.pem: unit/cert-client-key-pkcs8.pem
	$(AM_V_GEN)openssl pkcs8 -in $< -out $@ \
			-topk8 -v2 des-cbc -v2prf hmacWithSHA1 -passout pass:abc

unit/cert-client-key-v2-des-ede3.pem: unit/cert-client-key-pkcs8.pem
	$(AM_V_GEN)openssl pkcs8 -in $< -out $@ \
			-topk8 -v2 des-ede3-cbc -v2prf hmacWithSHA224 -passout pass:abc

unit/cert-client-key-v2-aes128.pem: unit/cert-client-key-pkcs8.pem
	$(AM_V_GEN)openssl pkcs8 -in $< -out $@ \
			-topk8 -v2 aes128 -v2prf hmacWithSHA256 -passout pass:abc

unit/cert-client-key-v2-aes256.pem: unit/cert-client-key-pkcs8.pem
	$(AM_V_GEN)openssl pkcs8 -in $< -out $@ \
			-topk8 -v2 aes256 -v2prf hmacWithSHA512 -passout pass:abc

unit/cert-client.csr: unit/cert-client-key.pem unit/gencerts.cnf
	$(AM_V_GEN)openssl req -new -extensions cert_ext \
			-config $(srcdir)/unit/gencerts.cnf \
			-subj '/O=Bar Example Organization/CN=Bar Example Organization/emailAddress=bar@mail.example' \
			-key $< -out $@

unit/cert-client.pem: unit/cert-client.csr unit/cert-ca.pem unit/gencerts.cnf
	$(AM_V_GEN)openssl x509 -req -extensions cert_ext \
			-extfile $(srcdir)/unit/gencerts.cnf \
			-in $< -CA $(builddir)/unit/cert-ca.pem \
			-CAkey $(builddir)/unit/cert-ca-key.pem \
			-CAserial $(builddir)/unit/cert-ca.srl \
			-CAcreateserial -sha256 -days 10000 -out $@ $($(AM_V_P)_redirect_openssl)

unit/cert-client: unit/cert-client.pem unit/cert-ca.pem
	$(AM_V_GEN)openssl verify -CAfile $(builddir)/unit/cert-ca.pem $<

unit/cert-intca-key.pem:
	$(AM_V_GEN)openssl genrsa -out $@ $($(AM_V_P)_redirect_openssl)

unit/cert-intca.csr: unit/cert-intca-key.pem unit/gencerts.cnf
	$(AM_V_GEN)openssl req -new -extensions int_ext \
			-config $(srcdir)/unit/gencerts.cnf \
			-subj '/O=International Union of Example Organizations/CN=Certificate issuer guy/emailAddress=ca@mail.example' \
			-key $< -out $@

unit/cert-intca.pem: unit/cert-intca.csr unit/cert-ca.pem unit/gencerts.cnf
	$(AM_V_GEN)openssl x509 -req -extensions int_ext \
			-extfile $(srcdir)/unit/gencerts.cnf \
			-in $< -CA $(builddir)/unit/cert-ca.pem \
			-CAkey $(builddir)/unit/cert-ca-key.pem \
			-CAserial $(builddir)/unit/cert-ca.srl \
			-CAcreateserial -sha256 -days 10000 -out $@ $($(AM_V_P)_redirect_openssl)

unit/cert-intca: unit/cert-intca.pem unit/cert-ca.pem
	$(AM_V_GEN)openssl verify -CAfile $(builddir)/unit/cert-ca.pem $<

unit/cert-chain.pem: unit/cert-intca.pem unit/cert-ca.pem
	$(AM_V_GEN)cat $^ > $@

unit/cert-entity-int-key.pem:
	$(AM_V_GEN)openssl genrsa -out $@ $($(AM_V_P)_redirect_openssl)

unit/cert-entity-int.csr: unit/cert-entity-int-key.pem unit/gencerts.cnf
	$(AM_V_GEN)openssl req -new -extensions cert_ext \
			-config $(srcdir)/unit/gencerts.cnf \
			-subj '/O=Baz Example Organization/CN=Baz Example Organization/emailAddress=baz@mail.example' \
			-key $< -out $@

unit/cert-entity-int.pem: unit/cert-entity-int.csr unit/cert-intca.pem unit/gencerts.cnf
	$(AM_V_GEN)openssl x509 -req -extensions cert_ext \
			-extfile $(srcdir)/unit/gencerts.cnf \
			-in $< -CA $(builddir)/unit/cert-intca.pem \
			-CAkey $(builddir)/unit/cert-intca-key.pem \
			-CAserial $(builddir)/unit/cert-intca.srl \
			-CAcreateserial -sha256 -days 10000 -out $@ $($(AM_V_P)_redirect_openssl)

unit/cert-entity-int: unit/cert-entity-int.pem unit/cert-chain.pem
	$(AM_V_GEN)openssl verify -CAfile $(builddir)/unit/cert-chain.pem $<

unit/key-plaintext.h: unit/plaintext.txt
	$(AM_V_GEN)xxd -i < $< > $@

unit/key-ciphertext.dat: unit/plaintext.txt unit/cert-client.pem
	$(AM_V_GEN)openssl rsautl -encrypt -pkcs -in $< -certin \
			-inkey $(builddir)/unit/cert-client.pem -out $@

unit/key-ciphertext.h: unit/key-ciphertext.dat
	$(AM_V_GEN)xxd -i < $< > $@

unit/key-signature.dat: unit/plaintext.txt unit/cert-client-key.pem
	$(AM_V_GEN)openssl rsautl -sign -pkcs -in $< \
			-inkey $(builddir)/unit/cert-client-key.pem -out $@

unit/key-signature.h: unit/key-signature.dat
	$(AM_V_GEN)xxd -i < $< > $@

if MAINTAINER_MODE
BUILT_SOURCES = unit/key-plaintext.h unit/key-ciphertext.h unit/key-signature.h

check-local: $(cert_checks)
endif

clean-local:
	-rm -f unit/cert-*.pem unit/cert-*.csr unit/cert-*.srl unit/key-*.dat

maintainer-clean-local:
	-rm -rf build-aux
