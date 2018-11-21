/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2015  Intel Corporation. All rights reserved.
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

#include <ell/ell.h>

struct pem_test {
	const char *input;
	bool valid;
	const char *label;
	size_t decoded_size;
};

static const struct pem_test invalid_header1 = {
	.input = "-----BEGIN FOOBAR -----\r\n"
			"----END FOOBAR -----\r\n",
	.valid = false,
};

static const struct pem_test invalid_header2 = {
	.input = "-----BEGIN CERT  IFICATE-----\r\n"
			"-----END CERT  IFICATE----\r\n",
	.valid = false,
};

static const struct pem_test empty = {
	.input = "-----BEGIN CERTIFICATE-----\r\n"
			"-----END CERTIFICATE-----\r\n",
	.valid = false,
};

static const struct pem_test empty_label = {
	.input = "-----BEGIN -----\r\n"
			"U28/PHA+\r\n"
			"-----END -----\r\n",
	.valid = true,
	.label = "",
	.decoded_size = 6,
};

static void test_pem(const void *data)
{
	const struct pem_test *test = data;
	uint8_t *decoded;
	char *label;
	size_t decoded_size;

	decoded = l_pem_load_buffer((const uint8_t *) test->input,
					strlen(test->input), 0,
					&label, &decoded_size);

	if (!test->valid) {
		assert(!decoded);
		return;
	}

	assert(decoded);

	assert(!strcmp(test->label, label));
	assert(decoded_size == test->decoded_size);

	l_free(label);
	l_free(decoded);
}

static void test_encrypted_pkey(const void *data)
{
	const char *encrypted_pem = data;
	const char *plaintext_pem = CERTDIR "cert-client-key-pkcs8.pem";
	bool is_encrypted;
	size_t size;
	uint8_t encrypted1[256], encrypted2[256], plaintext[256];
	struct l_key *pkey1, *pkey2;
	bool is_public;

	is_encrypted = false;
	assert(!l_pem_load_private_key(encrypted_pem, NULL, &is_encrypted));
	assert(is_encrypted);

	is_encrypted = false;
	assert(!l_pem_load_private_key(encrypted_pem, "wrong-passwd",
					&is_encrypted));
	assert(is_encrypted);

	is_encrypted = false;
	pkey1 = l_pem_load_private_key(encrypted_pem, "abc", &is_encrypted);
	assert(pkey1);
	assert(is_encrypted);

	pkey2 = l_pem_load_private_key(plaintext_pem, NULL, &is_encrypted);
	assert(pkey2);
	assert(!is_encrypted);

	/*
	 * l_key_extract doesn't work for private keys so compare encrypt
	 * results instead of key exponent.
	 */
	memset(plaintext, 42, 256);
	assert(l_key_get_info(pkey1, L_KEY_RSA_RAW, L_CHECKSUM_NONE,
				&size, &is_public));
	assert(size == 2048);
	assert(!is_public);
	assert(l_key_encrypt(pkey1, L_KEY_RSA_RAW, L_CHECKSUM_NONE,
				plaintext, encrypted1, 256, 256) == 256);
	assert(l_key_encrypt(pkey2, L_KEY_RSA_RAW, L_CHECKSUM_NONE,
				plaintext, encrypted2, 256, 256) == 256);
	assert(!memcmp(encrypted1, encrypted2, 256));

	l_key_free(pkey1);
	l_key_free(pkey2);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("pem/invalid header/test 1", test_pem, &invalid_header1);
	l_test_add("pem/invalid header/test 2", test_pem, &invalid_header2);

	l_test_add("pem/empty", test_pem, &empty);

	l_test_add("pem/empty label", test_pem, &empty_label);

	if (!l_checksum_is_supported(L_CHECKSUM_MD5, false) ||
			!l_checksum_is_supported(L_CHECKSUM_SHA1, false) ||
			!l_cipher_is_supported(L_CIPHER_DES_CBC) ||
			!l_key_is_supported(L_KEY_FEATURE_CRYPTO))
		goto done;

	l_test_add("pem/v1 MD5AndDES encrypted Private Key",
			test_encrypted_pkey,
			CERTDIR "cert-client-key-md5-des.pem");
	l_test_add("pem/v1 SHA1AndDES encrypted Private Key",
			test_encrypted_pkey,
			CERTDIR "cert-client-key-sha1-des.pem");
	l_test_add("pem/v2 DES encrypted Private Key", test_encrypted_pkey,
			CERTDIR "cert-client-key-v2-des.pem");

	if (l_cipher_is_supported(L_CIPHER_DES3_EDE_CBC) &&
			l_checksum_is_supported(L_CHECKSUM_SHA224, false))
		l_test_add("pem/v2 DES EDE3 encrypted Private Key",
				test_encrypted_pkey,
				CERTDIR "cert-client-key-v2-des-ede3.pem");

	if (!l_cipher_is_supported(L_CIPHER_AES))
		goto done;

	if (l_checksum_is_supported(L_CHECKSUM_SHA256, false))
		l_test_add("pem/v2 AES128 encrypted Private Key",
				test_encrypted_pkey,
				CERTDIR "cert-client-key-v2-aes128.pem");

	if (l_checksum_is_supported(L_CHECKSUM_SHA512, false))
		l_test_add("pem/v2 AES256 encrypted Private Key",
				test_encrypted_pkey,
				CERTDIR "cert-client-key-v2-aes256.pem");

done:
	return l_test_run();
}
