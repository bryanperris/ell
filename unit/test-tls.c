/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011-2014  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <stdio.h>
#include <unistd.h>

#include <ell/ell.h>

#include "ell/tls-private.h"
#include "ell/cert-private.h"

static void test_tls10_prf(const void *data)
{
	/* Common 1.0 test vector, original URL dead */
	uint8_t secret[48] = {
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
	};
	char *label = "PRF Testvector";
	uint8_t seed[64] = {
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
	};
	uint8_t expected[104] = {
		0xd3, 0xd4, 0xd1, 0xe3, 0x49, 0xb5, 0xd5, 0x15,
		0x04, 0x46, 0x66, 0xd5, 0x1d, 0xe3, 0x2b, 0xab,
		0x25, 0x8c, 0xb5, 0x21, 0xb6, 0xb0, 0x53, 0x46,
		0x3e, 0x35, 0x48, 0x32, 0xfd, 0x97, 0x67, 0x54,
		0x44, 0x3b, 0xcf, 0x9a, 0x29, 0x65, 0x19, 0xbc,
		0x28, 0x9a, 0xbc, 0xbc, 0x11, 0x87, 0xe4, 0xeb,
		0xd3, 0x1e, 0x60, 0x23, 0x53, 0x77, 0x6c, 0x40,
		0x8a, 0xaf, 0xb7, 0x4c, 0xbc, 0x85, 0xef, 0xf6,
		0x92, 0x55, 0xf9, 0x78, 0x8f, 0xaa, 0x18, 0x4c,
		0xbb, 0x95, 0x7a, 0x98, 0x19, 0xd8, 0x4a, 0x5d,
		0x7e, 0xb0, 0x06, 0xeb, 0x45, 0x9d, 0x3a, 0xe8,
		0xde, 0x98, 0x10, 0x45, 0x4b, 0x8b, 0x2d, 0x8f,
		0x1a, 0xfb, 0xc6, 0x55, 0xa8, 0xc9, 0xa0, 0x13
	};
	uint8_t out_buf[104];

	tls10_prf(secret, sizeof(secret), label, seed, sizeof(seed),
			out_buf, sizeof(expected));

	assert(!memcmp(out_buf, expected, sizeof(expected)));
}

/* https://www.ietf.org/mail-archive/web/tls/current/msg03416.html */
static struct tls12_prf_test {
	enum l_checksum_type hash;
	const uint8_t *secret;
	size_t secret_len;
	const char *label;
	const uint8_t *seed;
	size_t seed_len;
	const uint8_t *expected;
	size_t out_len;
} tls12_prf_sha256_0 = {
	.hash = L_CHECKSUM_SHA256,
	.secret_len = 16,
	.secret = (const uint8_t []) {
		0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17,
		0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71, 0xdb, 0x35,
	},
	.seed_len = 16,
	.seed = (const uint8_t []) {
		0xa0, 0xba, 0x9f, 0x93, 0x6c, 0xda, 0x31, 0x18,
		0x27, 0xa6, 0xf7, 0x96, 0xff, 0xd5, 0x19, 0x8c,
	},
	.label = "test label",
	.out_len = 100,
	.expected = (const uint8_t []) {
		0xe3, 0xf2, 0x29, 0xba, 0x72, 0x7b, 0xe1, 0x7b,
		0x8d, 0x12, 0x26, 0x20, 0x55, 0x7c, 0xd4, 0x53,
		0xc2, 0xaa, 0xb2, 0x1d, 0x07, 0xc3, 0xd4, 0x95,
		0x32, 0x9b, 0x52, 0xd4, 0xe6, 0x1e, 0xdb, 0x5a,
		0x6b, 0x30, 0x17, 0x91, 0xe9, 0x0d, 0x35, 0xc9,
		0xc9, 0xa4, 0x6b, 0x4e, 0x14, 0xba, 0xf9, 0xaf,
		0x0f, 0xa0, 0x22, 0xf7, 0x07, 0x7d, 0xef, 0x17,
		0xab, 0xfd, 0x37, 0x97, 0xc0, 0x56, 0x4b, 0xab,
		0x4f, 0xbc, 0x91, 0x66, 0x6e, 0x9d, 0xef, 0x9b,
		0x97, 0xfc, 0xe3, 0x4f, 0x79, 0x67, 0x89, 0xba,
		0xa4, 0x80, 0x82, 0xd1, 0x22, 0xee, 0x42, 0xc5,
		0xa7, 0x2e, 0x5a, 0x51, 0x10, 0xff, 0xf7, 0x01,
		0x87, 0x34, 0x7b, 0x66,
	},
}, tls12_prf_sha384_0 = {
	.hash = L_CHECKSUM_SHA384,
	.secret_len = 16,
	.secret = (const uint8_t []) {
		0xb8, 0x0b, 0x73, 0x3d, 0x6c, 0xee, 0xfc, 0xdc,
		0x71, 0x56, 0x6e, 0xa4, 0x8e, 0x55, 0x67, 0xdf,
	},
	.seed_len = 16,
	.seed = (const uint8_t []) {
		0xcd, 0x66, 0x5c, 0xf6, 0xa8, 0x44, 0x7d, 0xd6,
		0xff, 0x8b, 0x27, 0x55, 0x5e, 0xdb, 0x74, 0x65,
	},
	.label = "test label",
	.out_len = 148,
	.expected = (const uint8_t []) {
		0x7b, 0x0c, 0x18, 0xe9, 0xce, 0xd4, 0x10, 0xed,
		0x18, 0x04, 0xf2, 0xcf, 0xa3, 0x4a, 0x33, 0x6a,
		0x1c, 0x14, 0xdf, 0xfb, 0x49, 0x00, 0xbb, 0x5f,
		0xd7, 0x94, 0x21, 0x07, 0xe8, 0x1c, 0x83, 0xcd,
		0xe9, 0xca, 0x0f, 0xaa, 0x60, 0xbe, 0x9f, 0xe3,
		0x4f, 0x82, 0xb1, 0x23, 0x3c, 0x91, 0x46, 0xa0,
		0xe5, 0x34, 0xcb, 0x40, 0x0f, 0xed, 0x27, 0x00,
		0x88, 0x4f, 0x9d, 0xc2, 0x36, 0xf8, 0x0e, 0xdd,
		0x8b, 0xfa, 0x96, 0x11, 0x44, 0xc9, 0xe8, 0xd7,
		0x92, 0xec, 0xa7, 0x22, 0xa7, 0xb3, 0x2f, 0xc3,
		0xd4, 0x16, 0xd4, 0x73, 0xeb, 0xc2, 0xc5, 0xfd,
		0x4a, 0xbf, 0xda, 0xd0, 0x5d, 0x91, 0x84, 0x25,
		0x9b, 0x5b, 0xf8, 0xcd, 0x4d, 0x90, 0xfa, 0x0d,
		0x31, 0xe2, 0xde, 0xc4, 0x79, 0xe4, 0xf1, 0xa2,
		0x60, 0x66, 0xf2, 0xee, 0xa9, 0xa6, 0x92, 0x36,
		0xa3, 0xe5, 0x26, 0x55, 0xc9, 0xe9, 0xae, 0xe6,
		0x91, 0xc8, 0xf3, 0xa2, 0x68, 0x54, 0x30, 0x8d,
		0x5e, 0xaa, 0x3b, 0xe8, 0x5e, 0x09, 0x90, 0x70,
		0x3d, 0x73, 0xe5, 0x6f,
	},
}, tls12_prf_sha512_0 = {
	.hash = L_CHECKSUM_SHA512,
	.secret_len = 16,
	.secret = (const uint8_t []) {
		0xb0, 0x32, 0x35, 0x23, 0xc1, 0x85, 0x35, 0x99,
		0x58, 0x4d, 0x88, 0x56, 0x8b, 0xbb, 0x05, 0xeb,
	},
	.seed_len = 16,
	.seed = (const uint8_t []) {
		0xd4, 0x64, 0x0e, 0x12, 0xe4, 0xbc, 0xdb, 0xfb,
		0x43, 0x7f, 0x03, 0xe6, 0xae, 0x41, 0x8e, 0xe5,
	},
	.label = "test label",
	.out_len = 196,
	.expected = (const uint8_t []) {
		0x12, 0x61, 0xf5, 0x88, 0xc7, 0x98, 0xc5, 0xc2,
		0x01, 0xff, 0x03, 0x6e, 0x7a, 0x9c, 0xb5, 0xed,
		0xcd, 0x7f, 0xe3, 0xf9, 0x4c, 0x66, 0x9a, 0x12,
		0x2a, 0x46, 0x38, 0xd7, 0xd5, 0x08, 0xb2, 0x83,
		0x04, 0x2d, 0xf6, 0x78, 0x98, 0x75, 0xc7, 0x14,
		0x7e, 0x90, 0x6d, 0x86, 0x8b, 0xc7, 0x5c, 0x45,
		0xe2, 0x0e, 0xb4, 0x0c, 0x1c, 0xf4, 0xa1, 0x71,
		0x3b, 0x27, 0x37, 0x1f, 0x68, 0x43, 0x25, 0x92,
		0xf7, 0xdc, 0x8e, 0xa8, 0xef, 0x22, 0x3e, 0x12,
		0xea, 0x85, 0x07, 0x84, 0x13, 0x11, 0xbf, 0x68,
		0x65, 0x3d, 0x0c, 0xfc, 0x40, 0x56, 0xd8, 0x11,
		0xf0, 0x25, 0xc4, 0x5d, 0xdf, 0xa6, 0xe6, 0xfe,
		0xc7, 0x02, 0xf0, 0x54, 0xb4, 0x09, 0xd6, 0xf2,
		0x8d, 0xd0, 0xa3, 0x23, 0x3e, 0x49, 0x8d, 0xa4,
		0x1a, 0x3e, 0x75, 0xc5, 0x63, 0x0e, 0xed, 0xbe,
		0x22, 0xfe, 0x25, 0x4e, 0x33, 0xa1, 0xb0, 0xe9,
		0xf6, 0xb9, 0x82, 0x66, 0x75, 0xbe, 0xc7, 0xd0,
		0x1a, 0x84, 0x56, 0x58, 0xdc, 0x9c, 0x39, 0x75,
		0x45, 0x40, 0x1d, 0x40, 0xb9, 0xf4, 0x6c, 0x7a,
		0x40, 0x0e, 0xe1, 0xb8, 0xf8, 0x1c, 0xa0, 0xa6,
		0x0d, 0x1a, 0x39, 0x7a, 0x10, 0x28, 0xbf, 0xf5,
		0xd2, 0xef, 0x50, 0x66, 0x12, 0x68, 0x42, 0xfb,
		0x8d, 0xa4, 0x19, 0x76, 0x32, 0xbd, 0xb5, 0x4f,
		0xf6, 0x63, 0x3f, 0x86, 0xbb, 0xc8, 0x36, 0xe6,
		0x40, 0xd4, 0xd8, 0x98,
	},
};

static void test_tls12_prf(const void *data)
{
	const struct tls12_prf_test *test = data;
	uint8_t out_buf[test->out_len];

	tls12_prf(test->hash, test->secret, test->secret_len,
			test->label, test->seed, test->seed_len,
			out_buf, test->out_len);

	assert(!memcmp(out_buf, test->expected, test->out_len));
}

static struct l_cert *load_cert_file(const char *filename)
{
	uint8_t *der;
	size_t len;
	char *label;
	struct l_cert *cert;

	der = l_pem_load_file(filename, 0, &label, &len);
	if (!der)
		return NULL;

	l_free(label);
	cert = l_cert_new_from_der(der, len);
	l_free(der);
	return cert;
}

static void test_certificates(const void *data)
{
	struct l_queue *cacert;
	struct l_queue *wrongca;
	struct l_queue *twocas;
	struct l_certchain *chain;
	struct l_certchain *chain2;
	struct l_certchain *chain3;
	struct l_certchain *chain4;

	cacert = l_pem_load_certificate_list(CERTDIR "cert-ca.pem");
	assert(cacert && !l_queue_isempty(cacert));

	wrongca = l_pem_load_certificate_list(CERTDIR "cert-intca.pem");
	assert(wrongca && !l_queue_isempty(wrongca));

	twocas = l_pem_load_certificate_list(CERTDIR "cert-chain.pem");
	assert(twocas);

	chain = l_pem_load_certificate_chain(CERTDIR "cert-server.pem");
	assert(chain);

	assert(!l_certchain_verify(chain, wrongca, NULL));
	assert(l_certchain_verify(chain, cacert, NULL));
	assert(l_certchain_verify(chain, NULL, NULL));
	assert(l_certchain_verify(chain, twocas, NULL));

	chain2 = l_pem_load_certificate_chain(CERTDIR "cert-chain.pem");
	assert(chain2);

	assert(!l_certchain_verify(chain2, wrongca, NULL));
	assert(l_certchain_verify(chain2, cacert, NULL));
	assert(l_certchain_verify(chain2, NULL, NULL));
	assert(l_certchain_verify(chain2, twocas, NULL));

	chain3 = certchain_new_from_leaf(
			load_cert_file(CERTDIR "cert-server.pem"));
	certchain_link_issuer(chain3,
			load_cert_file(CERTDIR "cert-entity-int.pem"));
	certchain_link_issuer(chain3,
			load_cert_file(CERTDIR "cert-intca.pem"));
	certchain_link_issuer(chain3,
			load_cert_file(CERTDIR "cert-ca.pem"));
	assert(chain3);

	assert(!l_certchain_verify(chain3, wrongca, NULL));
	assert(!l_certchain_verify(chain3, cacert, NULL));
	assert(!l_certchain_verify(chain3, NULL, NULL));
	assert(!l_certchain_verify(chain3, twocas, NULL));

	chain4 = certchain_new_from_leaf(
			load_cert_file(CERTDIR "cert-entity-int.pem"));
	certchain_link_issuer(chain4,
			load_cert_file(CERTDIR "cert-intca.pem"));
	certchain_link_issuer(chain4,
			load_cert_file(CERTDIR "cert-ca.pem"));
	assert(chain4);

	assert(!l_certchain_verify(chain4, wrongca, NULL));
	assert(l_certchain_verify(chain4, cacert, NULL));
	assert(l_certchain_verify(chain4, NULL, NULL));
	assert(l_certchain_verify(chain4, twocas, NULL));

	l_certchain_free(chain);
	l_certchain_free(chain2);
	l_certchain_free(chain3);
	l_certchain_free(chain4);
	l_queue_destroy(cacert, (l_queue_destroy_func_t) l_cert_free);
	l_queue_destroy(wrongca, (l_queue_destroy_func_t) l_cert_free);
	l_queue_destroy(twocas, (l_queue_destroy_func_t) l_cert_free);
}

struct tls_conn_test {
	const char *server_cert_path;
	const char *server_key_path;
	const char *server_key_passphrase;
	const char *server_ca_cert_path;
	const char *server_expect_identity;
	const char **server_cipher_suites;
	const char *client_cert_path;
	const char *client_key_path;
	const char *client_key_passphrase;
	const char *client_ca_cert_path;
	const char *client_expect_identity;
	const char **client_cipher_suites;
	bool expect_alert;
	bool expect_client_start_fail;
	enum l_tls_alert_desc alert_desc;
};

static const struct tls_conn_test tls_conn_test_no_auth = {
	.server_cert_path = CERTDIR "cert-server.pem",
	.server_key_path = CERTDIR "cert-server-key-pkcs8.pem",
	.server_expect_identity = NULL,
	.client_expect_identity = NULL,
};

static const struct tls_conn_test tls_conn_test_server_auth = {
	.server_cert_path = CERTDIR "cert-server.pem",
	.server_key_path = CERTDIR "cert-server-key-pkcs8.pem",
	.server_expect_identity = NULL,
	.client_ca_cert_path = CERTDIR "cert-ca.pem",
	.client_expect_identity = "Foo Example Organization",
};

static const struct tls_conn_test tls_conn_test_client_auth_attempt = {
	.server_cert_path = CERTDIR "cert-server.pem",
	.server_key_path = CERTDIR "cert-server-key-pkcs8.pem",
	.server_ca_cert_path = CERTDIR "cert-ca.pem",
	.server_expect_identity = NULL,
	.client_expect_identity = NULL,
};

static const struct tls_conn_test tls_conn_test_client_auth = {
	.server_cert_path = CERTDIR "cert-server.pem",
	.server_key_path = CERTDIR "cert-server-key-pkcs8.pem",
	.server_ca_cert_path = CERTDIR "cert-ca.pem",
	.server_expect_identity = "Bar Example Organization",
	.client_cert_path = CERTDIR "cert-client.pem",
	.client_key_path = CERTDIR "cert-client-key-pkcs8.pem",
	.client_expect_identity = NULL,
};

static const struct tls_conn_test tls_conn_test_full_auth_attempt = {
	.server_cert_path = CERTDIR "cert-server.pem",
	.server_key_path = CERTDIR "cert-server-key-pkcs8.pem",
	.server_ca_cert_path = CERTDIR "cert-ca.pem",
	.server_expect_identity = NULL,
	.client_ca_cert_path = CERTDIR "cert-ca.pem",
	.client_expect_identity = "Foo Example Organization",
};

static const struct tls_conn_test tls_conn_test_full_auth = {
	.server_cert_path = CERTDIR "cert-server.pem",
	.server_key_path = CERTDIR "cert-server-key-pkcs8.pem",
	.server_ca_cert_path = CERTDIR "cert-ca.pem",
	.server_expect_identity = "Bar Example Organization",
	.client_cert_path = CERTDIR "cert-client.pem",
	.client_key_path = CERTDIR "cert-client-key-pkcs8.pem",
	.client_ca_cert_path = CERTDIR "cert-ca.pem",
	.client_expect_identity = "Foo Example Organization",
};

static const struct tls_conn_test tls_conn_test_bad_client_suite = {
	.server_cert_path = CERTDIR "cert-server.pem",
	.server_key_path = CERTDIR "cert-server-key-pkcs8.pem",
	.server_ca_cert_path = CERTDIR "cert-ca.pem",
	.server_expect_identity = "Bar Example Organization",
	.client_cert_path = CERTDIR "cert-client.pem",
	.client_key_path = CERTDIR "cert-client-key-pkcs8.pem",
	.client_ca_cert_path = CERTDIR "cert-ca.pem",
	.client_expect_identity = "Foo Example Organization",
	.client_cipher_suites = (const char *[]) { "UNKNOWN", NULL },
	.expect_client_start_fail = true,
};

static const struct tls_conn_test tls_conn_test_suite_mismatch = {
	.server_cert_path = CERTDIR "cert-server.pem",
	.server_key_path = CERTDIR "cert-server-key-pkcs8.pem",
	.server_ca_cert_path = CERTDIR "cert-ca.pem",
	.server_expect_identity = "Bar Example Organization",
	.server_cipher_suites =
		(const char *[]) { "TLS_RSA_WITH_AES_128_CBC_SHA256", NULL },
	.client_cert_path = CERTDIR "cert-client.pem",
	.client_key_path = CERTDIR "cert-client-key-pkcs8.pem",
	.client_ca_cert_path = CERTDIR "cert-ca.pem",
	.client_expect_identity = "Foo Example Organization",
	.client_cipher_suites =
		(const char *[]) { "TLS_RSA_WITH_AES_256_CBC_SHA256", NULL },
	.expect_alert = true,
	.alert_desc = TLS_ALERT_INSUFFICIENT_SECURITY,
};

static const struct tls_conn_test tls_conn_test_version_mismatch = {
	.server_cert_path = CERTDIR "cert-server.pem",
	.server_key_path = CERTDIR "cert-server-key-pkcs8.pem",
	.server_ca_cert_path = CERTDIR "cert-ca.pem",
	.server_expect_identity = "Bar Example Organization",
	.client_cert_path = CERTDIR "cert-client.pem",
	.client_key_path = CERTDIR "cert-client-key-pkcs8.pem",
	.client_ca_cert_path = CERTDIR "cert-ca.pem",
	.client_expect_identity = "Foo Example Organization",
	.expect_alert = true,
	.alert_desc = TLS_ALERT_PROTOCOL_VERSION,
};

#define identity_compare(a, b) ((!(a) && !(b)) || ((a) && (b) && !strcmp(a, b)))

struct tls_test_state {
	struct l_tls *tls;

	bool ready, success;

	uint8_t raw_buf[16384];
	int raw_buf_len;

	uint8_t plaintext_buf[128];
	int plaintext_buf_len;

	const char *send_data;
	const char *expect_data;
	const char *expect_peer;

	bool expect_alert;
	enum l_tls_alert_desc alert_desc;
};

static void tls_test_new_data(const uint8_t *data, size_t len, void *user_data)
{
	struct tls_test_state *s = user_data;

	assert(s->ready);
	assert(s->plaintext_buf_len + len <= strlen(s->expect_data));

	memcpy(s->plaintext_buf + s->plaintext_buf_len, data, len);
	s->plaintext_buf_len += len;

	if (s->plaintext_buf_len == (int) strlen(s->expect_data) &&
			!memcmp(s->plaintext_buf, s->expect_data,
				s->plaintext_buf_len))
		s->success = true;
}

static void tls_test_write(const uint8_t *data, size_t len, void *user_data)
{
	struct tls_test_state *s = user_data;

	assert(s->raw_buf_len + len <= sizeof(s->raw_buf));

	memcpy(s->raw_buf + s->raw_buf_len, data, len);
	s->raw_buf_len += len;
}

static void tls_test_ready(const char *peer_identity, void *user_data)
{
	struct tls_test_state *s = user_data;

	assert(!s->ready);
	assert(!s->expect_alert);
	assert((!s->expect_peer && !peer_identity) ||
			(s->expect_peer && peer_identity &&
			 !strcmp(s->expect_peer, peer_identity)));
	s->ready = true;

	l_tls_write(s->tls, (const uint8_t *) s->send_data,
			strlen(s->send_data));
}

static void tls_test_disconnected(enum l_tls_alert_desc reason, bool remote,
					void *user_data)
{
	struct tls_test_state *s = user_data;

	assert(s->expect_alert);
	assert(reason == s->alert_desc);
	s->success = true;
}

static void tls_debug_cb(const char *str, void *user_data)
{
	l_info("%s %s", (const char *) user_data, str);
}

static void test_tls_with_ver(const struct tls_conn_test *test,
				uint16_t server_ver, uint16_t client_ver)
{
	bool auth_ok;
	struct tls_test_state s[2] = {
		{
			.ready = false,
			.success = false,
			.raw_buf_len = 0,
			.plaintext_buf_len = 0,
			.send_data = "server to client",
			.expect_data = "client to server",
			.expect_peer = test->server_expect_identity,
			.expect_alert = test->expect_alert,
			.alert_desc = test->alert_desc,
		},
		{
			.ready = false,
			.success = false,
			.raw_buf_len = 0,
			.plaintext_buf_len = 0,
			.send_data = "client to server",
			.expect_data = "server to client",
			.expect_peer = test->client_expect_identity,
			.expect_alert = test->expect_alert,
			.alert_desc = test->alert_desc,
		},
	};

	/* Server */
	s[0].tls = l_tls_new(true, tls_test_new_data, tls_test_write,
				tls_test_ready, tls_test_disconnected, &s[0]);
	/* Client */
	s[1].tls = l_tls_new(false, tls_test_new_data, tls_test_write,
				tls_test_ready, tls_test_disconnected, &s[1]);

	assert(s[0].tls);
	assert(s[1].tls);

	if (server_ver)
		l_tls_set_version_range(s[0].tls, server_ver, server_ver);

	if (client_ver)
		l_tls_set_version_range(s[1].tls, client_ver, client_ver);

	if (test->server_cipher_suites)
		tls_set_cipher_suites(s[0].tls, test->server_cipher_suites);

	if (test->client_cipher_suites)
		tls_set_cipher_suites(s[1].tls, test->client_cipher_suites);

	if (getenv("TLS_SERVER_DEBUG"))
		l_tls_set_debug(s[0].tls, tls_debug_cb, "server", NULL);

	if (getenv("TLS_DEBUG"))
		l_tls_set_debug(s[1].tls, tls_debug_cb, "client", NULL);

	auth_ok = l_tls_set_auth_data(s[0].tls, test->server_cert_path,
					test->server_key_path,
					test->server_key_passphrase);
	assert(auth_ok);
	auth_ok = l_tls_set_auth_data(s[1].tls, test->client_cert_path,
					test->client_key_path,
					test->client_key_passphrase);
	assert(auth_ok);
	assert(l_tls_set_cacert(s[0].tls, test->server_ca_cert_path));
	assert(l_tls_set_cacert(s[1].tls, test->client_ca_cert_path));

	assert(l_tls_start(s[0].tls));
	assert(!!l_tls_start(s[1].tls) == !test->expect_client_start_fail);

	if (test->expect_client_start_fail)
		goto done;

	while (!(test->expect_alert && s[0].success && s[1].success)) {
		if (s[0].raw_buf_len) {
			l_tls_handle_rx(s[1].tls, s[0].raw_buf,
					s[0].raw_buf_len);
			s[0].raw_buf_len = 0;
		} else if (s[1].raw_buf_len) {
			l_tls_handle_rx(s[0].tls, s[1].raw_buf,
					s[1].raw_buf_len);
			s[1].raw_buf_len = 0;
		} else
			break;
	}

	assert(s[0].success && s[1].success);

done:
	l_tls_free(s[0].tls);
	l_tls_free(s[1].tls);
}

static void test_tls_test(const void *data)
{
	const struct tls_conn_test *test = data;

	/*
	 * 1.2 should get negotiated in the first case.  If the three
	 * scenarios succeed that's already good but can be checked with:
	 * $ TLS_DEBUG=1 unit/test-tls 2>&1 | grep "Negotiated"
	 */
	test_tls_with_ver(test, 0, 0);
	test_tls_with_ver(test, 0, L_TLS_V11);
	test_tls_with_ver(test, L_TLS_V10, 0);
}

static void test_tls_version_mismatch_test(const void *data)
{
	test_tls_with_ver(&tls_conn_test_version_mismatch,
				L_TLS_V11, L_TLS_V12);
	test_tls_with_ver(&tls_conn_test_version_mismatch,
				L_TLS_V12, L_TLS_V10);
	test_tls_with_ver(&tls_conn_test_version_mismatch,
				L_TLS_V10, L_TLS_V11);
}

static void test_tls_suite_test(const void *data)
{
	const char *suite_name = data;
	const char *client_cipher_suites[] = { suite_name, NULL };
	struct tls_conn_test test = tls_conn_test_full_auth;

	test.client_cipher_suites = client_cipher_suites;
	test_tls_with_ver(&test, 0, 0);
}

static int read_int_from_file(const char *path)
{
	int ret;
	FILE *file;

	file = fopen(path, "r");
	if (!file)
		return 0;

	if (fscanf(file, "%i", &ret) < 1)
		ret = 0;

	fclose(file);
	return ret;
}

int main(int argc, char *argv[])
{
	unsigned int i;
	int maxkeys;

	l_test_init(&argc, &argv);

	if (!l_checksum_is_supported(L_CHECKSUM_MD5, false) ||
			!l_checksum_is_supported(L_CHECKSUM_SHA1, false) ||
			!l_checksum_is_supported(L_CHECKSUM_SHA256, false) ||
			!l_checksum_is_supported(L_CHECKSUM_SHA384, false) ||
			!l_checksum_is_supported(L_CHECKSUM_SHA512, false)) {
		printf("Needed checksum missing, skipping...\n");
		goto done;
	}

	l_test_add("TLS 1.0 PRF", test_tls10_prf, NULL);

	l_test_add("TLS 1.2 PRF with SHA256", test_tls12_prf,
			&tls12_prf_sha256_0);

	l_test_add("TLS 1.2 PRF with SHA384", test_tls12_prf,
			&tls12_prf_sha384_0);

	l_test_add("TLS 1.2 PRF with SHA512", test_tls12_prf,
			&tls12_prf_sha512_0);

	if (l_key_is_supported(L_KEY_FEATURE_RESTRICT))
		l_test_add("Certificate chains", test_certificates, NULL);

	if (!l_getrandom_is_supported()) {
		printf("getrandom missing, skipping TLS connection tests...\n");
		goto done;
	}

	if (!l_cipher_is_supported(L_CIPHER_DES3_EDE_CBC) ||
			!l_cipher_is_supported(L_CIPHER_AES_CBC) ||
			!l_cipher_is_supported(L_CIPHER_ARC4)) {
		printf("Needed ciphers missing, "
				"skipping TLS connection tests...\n");
		goto done;
	}

	if (!l_key_is_supported(L_KEY_FEATURE_RESTRICT |
				L_KEY_FEATURE_CRYPTO)) {
		printf("Kernel lacks key restrictions or crypto, "
			"skipping TLS connection tests...\n");
		goto done;
	}

	maxkeys = read_int_from_file(getuid() > 0 ?
					"/proc/sys/kernel/keys/maxkeys" :
					"/proc/sys/kernel/keys/root_maxkeys");
	if (maxkeys && maxkeys < 2000)
		printf("Running sysctl kernel.keys.%s=2000 is recommended\n",
			getuid() > 0 ? "maxkeys" : "root_maxkeys");

	l_test_add("TLS connection no auth", test_tls_test,
			&tls_conn_test_no_auth);
	l_test_add("TLS connection server auth", test_tls_test,
			&tls_conn_test_server_auth);
	l_test_add("TLS connection client auth attempt", test_tls_test,
			&tls_conn_test_client_auth_attempt);
	l_test_add("TLS connection client auth", test_tls_test,
			&tls_conn_test_client_auth);
	l_test_add("TLS connection full auth attempt", test_tls_test,
			&tls_conn_test_full_auth_attempt);
	l_test_add("TLS connection full auth", test_tls_test,
			&tls_conn_test_full_auth);

	l_test_add("TLS connection bad client cipher suite", test_tls_test,
			&tls_conn_test_bad_client_suite);
	l_test_add("TLS connection cipher suite mismatch", test_tls_test,
			&tls_conn_test_suite_mismatch);

	l_test_add("TLS connection version mismatch",
			test_tls_version_mismatch_test, NULL);

	for (i = 0; tls_cipher_suite_pref[i]; i++) {
		struct tls_cipher_suite *suite = tls_cipher_suite_pref[i];
		struct tls_bulk_encryption_algorithm *alg = suite->encryption;
		bool supported;

		if (alg->cipher_type == TLS_CIPHER_AEAD)
			supported = l_aead_cipher_is_supported(alg->l_aead_id);
		else
			supported = l_cipher_is_supported(alg->l_id);

		if (supported) {
			l_test_add(suite->name, test_tls_suite_test,
					suite->name);
		} else {
			printf("Skipping %s due to missing cipher support\n",
				suite->name);
		}
	}

done:
	return l_test_run();
}
