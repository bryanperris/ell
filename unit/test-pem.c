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
	const char *plaintext_pem = "unit/cert-client-key-pkcs8.pem";
	bool encrypted;
	size_t size1, size2;
	uint8_t *pkey1, *pkey2;

	encrypted = false;
	assert(!l_pem_load_private_key(encrypted_pem, NULL,
					&encrypted, &size1));
	assert(encrypted);

	encrypted = false;
	assert(!l_pem_load_private_key(encrypted_pem, "wrong-passwd",
					&encrypted, &size1));
	assert(encrypted);

	encrypted = false;
	pkey1 = l_pem_load_private_key(encrypted_pem, "abc",
					&encrypted, &size1);
	assert(pkey1);
	assert(encrypted);

	pkey2 = l_pem_load_private_key(plaintext_pem, NULL,
					&encrypted, &size2);
	assert(pkey2);
	assert(!encrypted);

	assert(size1 == size2);
	assert(!memcmp(pkey1, pkey2, size1));

	l_free(pkey1);
	l_free(pkey2);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("pem/invalid header/test 1", test_pem, &invalid_header1);
	l_test_add("pem/invalid header/test 2", test_pem, &invalid_header2);

	l_test_add("pem/empty", test_pem, &empty);

	l_test_add("pem/empty label", test_pem, &empty_label);

	l_test_add("pem/v1 MD5AndDES encrypted Private Key",
			test_encrypted_pkey,
			"unit/cert-client-key-md5-des.pem");
	l_test_add("pem/v1 SHA1AndDES encrypted Private Key",
			test_encrypted_pkey,
			"unit/cert-client-key-sha1-des.pem");
	l_test_add("pem/v2 DES encrypted Private Key", test_encrypted_pkey,
			"unit/cert-client-key-v2-des.pem");
	l_test_add("pem/v2 DES EDE3 encrypted Private Key", test_encrypted_pkey,
			"unit/cert-client-key-v2-des-ede3.pem");
	l_test_add("pem/v2 AES128 encrypted Private Key", test_encrypted_pkey,
			"unit/cert-client-key-v2-aes128.pem");
	l_test_add("pem/v2 AES256 encrypted Private Key", test_encrypted_pkey,
			"unit/cert-client-key-v2-aes256.pem");

	return l_test_run();
}
