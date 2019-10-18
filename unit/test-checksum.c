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

#include <alloca.h>
#include <assert.h>

#include <ell/ell.h>

static char FIXED_STR[] =
	"The quick brown fox jumps over the lazy dog. "
	"Jackdaws love my big sphinx of quartz. "
	"Pack my box with five dozen liquor jugs. "
	"How razorback-jumping frogs can level six piqued gymnasts!";

#define FIXED_LEN  (strlen (FIXED_STR))

static void test_unsupported(const void *data)
{
	struct l_checksum *checksum;

	checksum = l_checksum_new(42);
	assert(!checksum);
}

static void test_md4(const void *data)
{
	struct l_checksum *checksum;
	unsigned char digest[16];
	unsigned char *expected;
	size_t expectlen;

	checksum = l_checksum_new(L_CHECKSUM_MD4);
	assert(checksum);

	l_checksum_update(checksum, FIXED_STR, FIXED_LEN);

	l_checksum_get_digest(checksum, digest, sizeof(digest));

	expected = l_util_from_hexstring("be3de05811bec433af48270014a8df0e",
						&expectlen);
	assert(expectlen == sizeof(digest));
	assert(!memcmp(digest, expected, expectlen));

	l_free(expected);
	l_checksum_free(checksum);
}

static void test_md5(const void *data)
{
	struct l_checksum *checksum;
	unsigned char digest[16];
	unsigned char *expected;
	size_t expectlen;

	checksum = l_checksum_new(L_CHECKSUM_MD5);
	assert(checksum);

	l_checksum_update(checksum, FIXED_STR, FIXED_LEN);

	l_checksum_get_digest(checksum, digest, sizeof(digest));

	expected = l_util_from_hexstring("407b72260377f77f8e63e13dc09bda2c",
						&expectlen);
	assert(expectlen == sizeof(digest));
	assert(!memcmp(digest, expected, expectlen));

	l_free(expected);
	l_checksum_free(checksum);
}

static void test_sha1(const void *data)
{
	struct l_checksum *checksum;
	unsigned char digest[20];
	unsigned char *expected;
	size_t expectlen;

	checksum = l_checksum_new(L_CHECKSUM_SHA1);
	assert(checksum);

	l_checksum_update(checksum, FIXED_STR, FIXED_LEN);

	l_checksum_get_digest(checksum, digest, sizeof(digest));

	expected = l_util_from_hexstring(
		"8802f1d217906250585b75187b1ebfbb5c6cbcae", &expectlen);
	assert(expectlen == sizeof(digest));
	assert(!memcmp(digest, expected, expectlen));

	l_free(expected);
	l_checksum_free(checksum);
}

static void test_sha256(const void *data)
{
	struct l_checksum *checksum;
	unsigned char digest[32];
	unsigned char *expected;
	size_t expectlen;

	checksum = l_checksum_new(L_CHECKSUM_SHA256);
	assert(checksum);

	l_checksum_update(checksum, FIXED_STR, FIXED_LEN);

	l_checksum_get_digest(checksum, digest, sizeof(digest));

	expected = l_util_from_hexstring(
		"df3a0c35d5345d6d792415c1310bd458"
		"9cdf68bac96ed599d6bb0c1545ffc86c", &expectlen);
	assert(expectlen == sizeof(digest));
	assert(!memcmp(digest, expected, expectlen));

	l_free(expected);
	l_checksum_free(checksum);
}

static void test_reset(const void *data)
{
	struct l_checksum *checksum;
	unsigned char digest[16];

	checksum = l_checksum_new(L_CHECKSUM_MD5);
	assert(checksum);

	l_checksum_update(checksum, FIXED_STR, FIXED_LEN);
	l_checksum_reset(checksum);
	l_checksum_update(checksum, FIXED_STR, FIXED_LEN);
	l_checksum_get_digest(checksum, digest, sizeof(digest));

	l_checksum_free(checksum);
}

static void test_updatev(const void *data)
{
	struct l_checksum *checksum;
	unsigned char digest1[20];
	unsigned char digest2[20];
	struct iovec iov[2];

	checksum = l_checksum_new(L_CHECKSUM_SHA1);
	assert(checksum);

	l_checksum_update(checksum, FIXED_STR, FIXED_LEN);
	l_checksum_get_digest(checksum, digest1, sizeof(digest1));

	iov[0].iov_base = FIXED_STR;
	iov[0].iov_len = FIXED_LEN / 2;

	iov[1].iov_base = FIXED_STR + FIXED_LEN / 2;
	iov[1].iov_len = FIXED_LEN - FIXED_LEN / 2;

	l_checksum_updatev(checksum, iov, 2);
	l_checksum_get_digest(checksum, digest2, sizeof(digest2));

	assert(!memcmp(digest1, digest2, sizeof(digest1)));

	l_checksum_free(checksum);
}

struct aes_cmac_test_vector {
	char *plaintext;
	char *key;
	char *ciphertext;
};

/* Hash AES_CMAC tests based on Bluetooth Mesh published sample data */
static const struct aes_cmac_test_vector aes_cmac_test1 = {
	.plaintext = "74657374",
	.key = "00000000000000000000000000000000",
	.ciphertext = "b73cefbd641ef2ea598c2b6efb62f79c",
};

static const struct aes_cmac_test_vector aes_cmac_test2 = {
	.plaintext = "f7a2a44f8e8a8029064f173ddc1e2b00",
	.key = "4f90480c1871bfbffd16971f4d8d10b1",
	.ciphertext = "2ea6467aa3378c4c545eda62935b9b86",
};

static void test_aes_cmac(const void *data)
{
	struct l_checksum *checksum;
	char *encbuf;
	size_t encbuflen;
	char *decbuf;
	size_t decbuflen;
	int r;
	bool success;
	const struct aes_cmac_test_vector *tv = data;

	size_t ptlen;
	uint8_t *pt = l_util_from_hexstring(tv->plaintext, &ptlen);
	size_t keylen;
	uint8_t *key = l_util_from_hexstring(tv->key, &keylen);
	size_t ctlen;
	uint8_t *ct = l_util_from_hexstring(tv->ciphertext, &ctlen);

	assert(pt);
	assert(ct);
	assert(key);

	encbuflen = ctlen;
	encbuf = alloca(encbuflen);
	memset(encbuf, 0, encbuflen);
	decbuflen = ptlen;
	decbuf = alloca(decbuflen);
	memset(decbuf, 0, decbuflen);

	checksum = l_checksum_new_cmac_aes(key, keylen);
	assert(checksum);

	success = l_checksum_update(checksum, pt, ptlen);
	assert(success);

	ctlen = l_checksum_get_digest(checksum, encbuf, encbuflen);
	assert(ctlen == encbuflen);

	r = memcmp(encbuf, ct, ctlen);
	assert(!r);

	l_checksum_free(checksum);

	l_free(pt);
	l_free(key);
	l_free(ct);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("unsupported", test_unsupported, NULL);

	if (l_checksum_is_supported(L_CHECKSUM_MD4, false))
		l_test_add("md4-1", test_md4, NULL);

	if (l_checksum_is_supported(L_CHECKSUM_MD5, false))
		l_test_add("md5-1", test_md5, NULL);

	if (l_checksum_is_supported(L_CHECKSUM_SHA1, false)) {
		l_test_add("sha1-1", test_sha1, NULL);

		l_test_add("checksum reset", test_reset, NULL);
		l_test_add("checksum updatev", test_updatev, NULL);
	}

	if (l_checksum_is_supported(L_CHECKSUM_SHA256, false))
		l_test_add("sha256-1", test_sha256, NULL);

	if (l_checksum_cmac_aes_supported()) {
		l_test_add("aes-cmac-1", test_aes_cmac, &aes_cmac_test1);
		l_test_add("aes-cmac-2", test_aes_cmac, &aes_cmac_test2);
	}

	return l_test_run();
}
