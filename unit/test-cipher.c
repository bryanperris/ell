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
#include <alloca.h>

#include <ell/ell.h>

#define FIXED_STR  "The quick brown fox jumps over the lazy dog. " \
		   "Jackdaws love my big sphinx of quartz. "       \
		   "Pack my box with five dozen liquor jugs. "     \
		   "How razorback-jumping frogs can level six piqued gymnasts!"
#define FIXED_LEN  (strlen(FIXED_STR))

#define KEY_STR "This key has exactly _32_ bytes!"
#define KEY_LEN (strlen(KEY_STR))

static void test_unsupported(const void *data)
{
	struct l_cipher *cipher;

	cipher = l_cipher_new(42, KEY_STR, KEY_LEN);
	assert(!cipher);
}

static void test_aes(const void *data)
{
	struct l_cipher *cipher;
	char buf[256];
	int r;

	cipher = l_cipher_new(L_CIPHER_AES, KEY_STR, KEY_LEN);
	assert(cipher);

	memcpy(buf, FIXED_STR, FIXED_LEN);

	l_cipher_encrypt(cipher, buf, buf, FIXED_LEN);

	r = memcmp(buf, FIXED_STR, FIXED_LEN);
	assert(r);

	l_cipher_decrypt(cipher, buf, buf, FIXED_LEN);

	r = memcmp(buf, FIXED_STR, FIXED_LEN);
	assert(!r);

	l_cipher_free(cipher);
}

static void test_arc4(const void *data)
{
	struct l_cipher *cipher;
	char buf[256];
	int r;

	static const unsigned char expect_plaintext[] = {
		0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3,
	};
	static const unsigned char expect_pedia[] = {
		0x10, 0x21, 0xbf, 0x04, 0x20,
	};
	static const unsigned char expect_attack[] = {
		0x45, 0xa0, 0x1f, 0x64, 0x5f, 0xc3, 0x5b, 0x38, 0x35, 0x52,
		0x54, 0x4b, 0x9b, 0xf5,
	};

	cipher = l_cipher_new(L_CIPHER_ARC4, "Key", 3);
	assert(cipher);
	l_cipher_encrypt(cipher, "Plaintext", buf, 9);
	assert(!memcmp(buf, expect_plaintext, 9));
	l_cipher_free(cipher);

	cipher = l_cipher_new(L_CIPHER_ARC4, "Wiki", 4);
	assert(cipher);
	l_cipher_encrypt(cipher, "pedia", buf, 5);
	assert(!memcmp(buf, expect_pedia, 5));
	l_cipher_free(cipher);

	cipher = l_cipher_new(L_CIPHER_ARC4, "Secret", 6);
	assert(cipher);
	l_cipher_encrypt(cipher, "Attack at dawn", buf, 14);
	assert(!memcmp(buf, expect_attack, 14));
	l_cipher_free(cipher);

	cipher = l_cipher_new(L_CIPHER_ARC4, KEY_STR, KEY_LEN);
	assert(cipher);

	memcpy(buf, FIXED_STR, FIXED_LEN);

	l_cipher_encrypt(cipher, buf, buf, FIXED_LEN);

	r = memcmp(buf, FIXED_STR, FIXED_LEN);
	assert(r);

	l_cipher_decrypt(cipher, buf, buf, FIXED_LEN);

	r = memcmp(buf, FIXED_STR, FIXED_LEN);
	assert(!r);

	l_cipher_free(cipher);
}

struct ccm_test_vector {
	char *aad;
	char *plaintext;
	char *key;
	char *nonce;
	char *ciphertext;
	char *tag;
};

static const struct ccm_test_vector ccm_long_nonce = {
	.aad =
	"333b6b8fda49c6e671bad05c7e2cafa88bd47f9b0aef1a358bc87d04f26f6c82",
	.plaintext =
	"1293201eb30ddd693b2eb23c1e6c20d5add2202afc71679ca2eba14f73b77bcd",
	.key = "fa536cf6c309d45c1baaa658f674758d",
	.nonce = "e0c5241bf0014ca88511d73a30",
	.ciphertext =
	"2e54ebaa38da9a2b03a1147495565c31d07e793b01fd28b2adeacac6f76ae84e",
	.tag = "e0a03b982c5afc8a937373d7d2b0e7a3"
};

static const struct ccm_test_vector ccm_short_nonce = {
	.plaintext =
	"a3b3fdf26d213f83c5f656b00f77253b68959c188767d584914887602c787595",
	.aad =
	"fcc20524894b4603fefb8029eff485a513ce4753d0d3a27c3a2c69088fa7fab7",
	.key = "7d84efac51291e868c7b7702181a3936",
	.nonce = "1bb3e62620462a",
	.ciphertext =
	"3222192ee773cef4a87175b73b3875320f18b7e016d17d52fb01f0f6ca10bb5f",
	.tag = "ee007aafe91135c39855ebf3db96d7ff"
};

static const struct ccm_test_vector ccm_no_aad = {
	.plaintext =
	"90795fffab99cffdeee5cadafe448ea4df74c480f9d7e1e481ee49adeee2732a",
	.aad = "",
	.key = "7b3da7d5ef41b5eef19cf8fb4ca19519",
	.nonce = "96722de7516afb",
	.ciphertext =
	"9160dd0e0a8ddd13bf4acb0c6f3cf4794c5459d36a378cfb4a31e6b00840d78a",
	.tag = "efd1dc938802cd845a16f32a60eabd0f"
};

static void test_aes_ccm(const void *data)
{
	struct l_aead_cipher *cipher;
	char *encbuf;
	size_t encbuflen;
	char *decbuf;
	size_t decbuflen;
	int r;
	bool success;
	const struct ccm_test_vector *tv = data;

	size_t ptlen;
	uint8_t *pt = l_util_from_hexstring(tv->plaintext, &ptlen);
	size_t aadlen;
	uint8_t *aad = l_util_from_hexstring(tv->aad, &aadlen);
	size_t keylen;
	uint8_t *key = l_util_from_hexstring(tv->key, &keylen);
	size_t noncelen;
	uint8_t *nonce = l_util_from_hexstring(tv->nonce, &noncelen);
	size_t ctlen;
	uint8_t *ct = l_util_from_hexstring(tv->ciphertext, &ctlen);
	size_t taglen;
	uint8_t *tag = l_util_from_hexstring(tv->tag, &taglen);

	encbuflen = ctlen + taglen;
	encbuf = alloca(encbuflen);
	memset(encbuf, 0, encbuflen);
	decbuflen = ptlen;
	decbuf = alloca(decbuflen);
	memset(decbuf, 0, decbuflen);

	cipher = l_aead_cipher_new(L_AEAD_CIPHER_AES_CCM, key, keylen, taglen);
	assert(cipher);

	success = l_aead_cipher_encrypt(cipher, pt, ptlen, aad, aadlen,
					nonce, noncelen, encbuf, encbuflen);
	assert(success);

	r = memcmp(encbuf, ct, ctlen);
	assert(!r);
	r = memcmp(encbuf + ctlen, tag, taglen);
	assert(!r);

	success = l_aead_cipher_decrypt(cipher, encbuf, encbuflen, aad, aadlen,
					nonce, noncelen, decbuf, decbuflen);
	assert (success);

	r = memcmp(decbuf, pt, ptlen);
	assert(!r);

	l_aead_cipher_free(cipher);
	l_free(pt);
	l_free(key);
	l_free(aad);
	l_free(nonce);
	l_free(ct);
	l_free(tag);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("unsupported", test_unsupported, NULL);

	if (l_cipher_is_supported(L_CIPHER_AES))
		l_test_add("aes", test_aes, NULL);

	if (l_cipher_is_supported(L_CIPHER_ARC4))
		l_test_add("arc4", test_arc4, NULL);

	if (l_aead_cipher_is_supported(L_AEAD_CIPHER_AES_CCM)) {
		l_test_add("aes_ccm long nonce", test_aes_ccm, &ccm_long_nonce);
		l_test_add("aes_ccm short nonce", test_aes_ccm,
							&ccm_short_nonce);
		l_test_add("aes_ccm no AAD", test_aes_ccm, &ccm_no_aad);
	}

	return l_test_run();
}
